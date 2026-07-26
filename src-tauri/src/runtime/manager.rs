use super::engine::{EngineConfig, run};
use super::recovery;
use super::{RuntimeError, RuntimeSnapshot, RuntimeState, SharedRuntimeStatus};
use crate::config::AppConfig;
use crate::diagnostics::Diagnostics;
use crate::outbound::CancellationToken;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

struct Control {
    generation_counter: u64,
    active_generation: Option<u64>,
    recovery_generation: Option<u64>,
    worker: Option<JoinHandle<()>>,
    cancellation: Option<CancellationToken>,
}

pub struct RuntimeManager {
    config_directory: PathBuf,
    diagnostics: Arc<Diagnostics>,
    status: Arc<SharedRuntimeStatus>,
    control: Mutex<Control>,
}

impl Drop for RuntimeManager {
    fn drop(&mut self) {
        let control = self
            .control
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cancellation) = control.cancellation.take() {
            cancellation.cancel();
        }
        if let Some(worker) = control.worker.take() {
            let _ = worker.join();
        }
        control.active_generation = None;
        control.recovery_generation = None;
    }
}

impl RuntimeManager {
    pub fn new(config_directory: PathBuf) -> Self {
        Self {
            config_directory,
            diagnostics: Arc::new(Diagnostics::default()),
            status: Arc::new(SharedRuntimeStatus::default()),
            control: Mutex::new(Control {
                generation_counter: 0,
                active_generation: None,
                recovery_generation: None,
                worker: None,
                cancellation: None,
            }),
        }
    }

    pub fn start(&self, config: &AppConfig) -> Result<RuntimeSnapshot, RuntimeError> {
        config
            .validate()
            .map_err(|_| RuntimeError::InvalidConfiguration)?;
        let engine_config = EngineConfig::try_from(config)?;
        let recovery_path = recovery::journal_path(&self.config_directory);

        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.reap_finished_worker_locked(&mut control);
        if control.active_generation.is_some()
            || control.recovery_generation.is_some()
            || control.worker.is_some()
        {
            return Err(RuntimeError::AlreadyRunning);
        }
        if recovery_path.exists() {
            self.status.set(
                RuntimeState::RecoveryRequired,
                Some(&RuntimeError::RecoveryRequired),
            );
            return Err(RuntimeError::RecoveryRequired);
        }
        let generation = control.generation_counter.wrapping_add(1).max(1);
        control.generation_counter = generation;
        self.diagnostics.reset();
        self.status.set(RuntimeState::Starting, None);
        let cancellation = CancellationToken::default();
        let worker_cancellation = cancellation.clone();
        let diagnostics = Arc::clone(&self.diagnostics);
        let status = Arc::clone(&self.status);
        let (startup_sender, startup_receiver) = mpsc::sync_channel(1);
        let worker = match thread::Builder::new()
            .name("ss-direct-runtime".to_owned())
            .spawn(move || {
                run(
                    engine_config,
                    recovery_path,
                    diagnostics,
                    worker_cancellation,
                    status,
                    startup_sender,
                );
            }) {
            Ok(worker) => worker,
            Err(error) => {
                let error = RuntimeError::subsystem("runtime thread creation", error);
                self.status.set(RuntimeState::Failed, Some(&error));
                return Err(error);
            }
        };
        control.active_generation = Some(generation);
        control.worker = Some(worker);
        control.cancellation = Some(cancellation);
        drop(control);

        match startup_receiver.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(())) => Ok(self.snapshot()),
            Ok(Err(error)) => {
                self.finish_failed_start(generation, Some(&error));
                Err(error)
            }
            Err(_) => {
                self.fail_start_generation(generation, &RuntimeError::StartupTimeout);
                self.finish_failed_start(generation, Some(&RuntimeError::StartupTimeout));
                Err(RuntimeError::StartupTimeout)
            }
        }
    }

    pub fn stop(&self) -> Result<RuntimeSnapshot, RuntimeError> {
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.reap_finished_worker_locked(&mut control) {
            drop(control);
            return Ok(self.snapshot());
        }
        if control.recovery_generation.is_some() {
            return Err(RuntimeError::AlreadyRunning);
        }
        let Some(worker) = control.worker.take() else {
            return Err(RuntimeError::NotRunning);
        };
        let generation = control
            .active_generation
            .expect("a managed worker always has an active generation");
        self.status.begin_stopping();
        if let Some(cancellation) = control.cancellation.take() {
            cancellation.cancel();
        }
        drop(control);
        if worker.join().is_err() {
            let mut control = self
                .control
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if control.active_generation == Some(generation) {
                self.status
                    .set(RuntimeState::Failed, Some(&RuntimeError::WorkerPanicked));
                control.active_generation = None;
            }
            return Err(RuntimeError::WorkerPanicked);
        }
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if control.active_generation == Some(generation) {
            control.active_generation = None;
        }
        drop(control);
        Ok(self.snapshot())
    }

    pub fn recover(&self) -> Result<RuntimeSnapshot, RuntimeError> {
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.reap_finished_worker_locked(&mut control);
        if control.active_generation.is_some()
            || control.recovery_generation.is_some()
            || control.worker.is_some()
        {
            return Err(RuntimeError::AlreadyRunning);
        }
        let generation = control.generation_counter.wrapping_add(1).max(1);
        control.generation_counter = generation;
        control.recovery_generation = Some(generation);
        drop(control);
        let result = recovery::recover(&recovery::journal_path(&self.config_directory));
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if control.recovery_generation == Some(generation) {
            if result.is_ok() {
                self.status.set(RuntimeState::Stopped, None);
            }
            control.recovery_generation = None;
        }
        drop(control);
        result?;
        Ok(self.snapshot())
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.reap_finished_worker_locked(&mut control);
        drop(control);
        let status = self.status.get();
        let recovery_required = recovery::journal_path(&self.config_directory).exists();
        RuntimeSnapshot {
            platform: std::env::consts::OS,
            state: if recovery_required && status.state == RuntimeState::Stopped {
                RuntimeState::RecoveryRequired
            } else {
                status.state
            },
            tun_available: cfg!(windows),
            version: env!("CARGO_PKG_VERSION"),
            counters: self.diagnostics.snapshot().into(),
            last_error: status.last_error,
            recovery_required,
        }
    }

    fn fail_start_generation(&self, generation: u64, error: &RuntimeError) -> bool {
        let control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if control.active_generation != Some(generation) || control.worker.is_none() {
            return false;
        }
        self.status.set(RuntimeState::Failed, Some(error));
        if let Some(cancellation) = control.cancellation.as_ref() {
            cancellation.cancel();
        }
        true
    }

    fn finish_failed_start(&self, generation: u64, final_error: Option<&RuntimeError>) -> bool {
        let worker = {
            let mut control = self
                .control
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if control.active_generation != Some(generation) {
                return false;
            }
            let Some(worker) = control.worker.take() else {
                // Another operation owns the join for this generation. It is
                // also responsible for retiring the generation afterwards.
                return false;
            };
            if let Some(cancellation) = control.cancellation.take() {
                cancellation.cancel();
            }
            worker
        };
        let _ = worker.join();
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if control.active_generation == Some(generation) {
            if let Some(error) = final_error {
                self.status.set(RuntimeState::Failed, Some(error));
            }
            control.active_generation = None;
        }
        true
    }

    /// Reaps an already-completed runtime thread while the manager control lock
    /// is held. This makes abnormal exits observable and allows a later start
    /// instead of permanently returning `AlreadyRunning`.
    fn reap_finished_worker_locked(&self, control: &mut Control) -> bool {
        if !control.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            return false;
        }
        control.cancellation.take();
        let Some(worker) = control.worker.take() else {
            return false;
        };
        if worker.join().is_err() {
            self.status
                .set(RuntimeState::Failed, Some(&RuntimeError::WorkerPanicked));
        }
        control.active_generation = None;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn manager() -> RuntimeManager {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        RuntimeManager::new(
            std::env::temp_dir().join(format!("ss-runtime-manager-{}-{nonce}", std::process::id())),
        )
    }

    fn install_finished_worker(manager: &RuntimeManager) {
        let worker = thread::spawn(|| {});
        install_worker_and_wait(manager, worker);
    }

    fn install_worker_and_wait(manager: &RuntimeManager, worker: JoinHandle<()>) {
        let mut control = manager
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        control.generation_counter = control.generation_counter.wrapping_add(1).max(1);
        control.active_generation = Some(control.generation_counter);
        control.worker = Some(worker);
        control.cancellation = Some(CancellationToken::default());
        while !control.worker.as_ref().expect("test worker").is_finished() {
            thread::yield_now();
        }
    }

    #[test]
    fn snapshot_reaps_completed_worker_and_keeps_failure_visible() {
        let manager = manager();
        manager
            .status
            .set(RuntimeState::Failed, Some(&RuntimeError::WorkerPanicked));
        install_finished_worker(&manager);

        let snapshot = manager.snapshot();
        assert_eq!(snapshot.state, RuntimeState::Failed);
        assert_eq!(
            snapshot.last_error.as_deref(),
            Some("the Wintun runtime worker stopped")
        );
        let control = manager
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(control.worker.is_none());
        assert!(control.cancellation.is_none());
        assert!(control.active_generation.is_none());
        assert!(control.recovery_generation.is_none());
    }

    #[test]
    fn stop_reaps_an_already_failed_worker_without_overwriting_failed_state() {
        let manager = manager();
        manager
            .status
            .set(RuntimeState::Failed, Some(&RuntimeError::WorkerPanicked));
        install_finished_worker(&manager);

        let snapshot = manager.stop().unwrap();
        assert_eq!(snapshot.state, RuntimeState::Failed);
        assert_eq!(
            snapshot.last_error.as_deref(),
            Some("the Wintun runtime worker stopped")
        );
    }

    #[test]
    fn panicked_worker_is_reaped_and_reported_as_failed() {
        let manager = manager();
        manager.status.set(RuntimeState::Running, None);
        let worker = thread::spawn(|| panic!("synthetic runtime failure"));
        install_worker_and_wait(&manager, worker);

        let snapshot = manager.snapshot();
        assert_eq!(snapshot.state, RuntimeState::Failed);
        assert_eq!(
            snapshot.last_error.as_deref(),
            Some("the Wintun runtime worker stopped")
        );
        let control = manager
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(control.worker.is_none());
        assert!(control.active_generation.is_none());
        assert!(control.recovery_generation.is_none());
    }

    #[test]
    fn stale_failed_start_cannot_cancel_or_join_a_new_generation() {
        let manager = manager();
        let cancellation = CancellationToken::default();
        let worker = thread::spawn(|| {});
        {
            let mut control = manager
                .control
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            control.generation_counter = 2;
            control.active_generation = Some(2);
            control.worker = Some(worker);
            control.cancellation = Some(cancellation.clone());
            while !control.worker.as_ref().expect("test worker").is_finished() {
                thread::yield_now();
            }
        }

        assert!(!manager.fail_start_generation(1, &RuntimeError::StartupTimeout));
        assert!(!manager.finish_failed_start(1, Some(&RuntimeError::StartupTimeout)));
        assert!(!cancellation.is_cancelled());
        {
            let control = manager
                .control
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(control.active_generation, Some(2));
            assert!(control.worker.is_some());
        }

        let _ = manager.snapshot();
    }

    #[test]
    fn recovery_generation_blocks_other_control_operations() {
        let manager = manager();
        {
            let mut control = manager
                .control
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            control.generation_counter = 1;
            control.recovery_generation = Some(1);
        }

        assert!(matches!(
            manager.recover(),
            Err(RuntimeError::AlreadyRunning)
        ));
        assert!(matches!(manager.stop(), Err(RuntimeError::AlreadyRunning)));
        let control = manager
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(control.recovery_generation, Some(1));
        assert!(control.worker.is_none());
    }

    #[test]
    fn duplicate_start_does_not_replace_running_state_with_recovery_required() {
        let manager = manager();
        fs::create_dir_all(&manager.config_directory).unwrap();
        fs::write(
            recovery::journal_path(&manager.config_directory),
            b"synthetic active journal",
        )
        .unwrap();
        let cancellation = CancellationToken::default();
        let worker_cancellation = cancellation.clone();
        let worker = thread::spawn(move || {
            while !worker_cancellation.is_cancelled() {
                thread::yield_now();
            }
        });
        {
            let mut control = manager
                .control
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            control.generation_counter = 1;
            control.active_generation = Some(1);
            control.worker = Some(worker);
            control.cancellation = Some(cancellation);
        }
        manager.status.set(RuntimeState::Running, None);

        assert!(matches!(
            manager.start(&AppConfig::default()),
            Err(RuntimeError::AlreadyRunning)
        ));
        assert_eq!(manager.status.get().state, RuntimeState::Running);
    }
}
