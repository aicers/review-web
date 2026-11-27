//! Orders active query packet sends against settings changes.

use std::sync::Arc;

use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

/// A fair send gate shared with the application that calls [`crate::serve`].
///
/// Hold a read guard while checking the current settings and sending one
/// packet. Mutations that change what may be sent take the write side, so
/// their responses wait for sends checked against the previous settings.
#[derive(Clone, Debug, Default)]
pub struct ActiveQuerySendGate {
    lock: Arc<RwLock<()>>,
}

impl ActiveQuerySendGate {
    /// Acquires a guard for checking settings and sending one packet.
    ///
    /// The owned guard may cross `.await` and is released on drop. A reader
    /// queued after a waiting writer waits until that writer releases.
    #[must_use]
    pub async fn read(&self) -> ActiveQuerySendGuard {
        ActiveQuerySendGuard {
            _guard: Arc::clone(&self.lock).read_owned().await,
        }
    }

    pub(crate) async fn write(&self) -> OwnedRwLockWriteGuard<()> {
        Arc::clone(&self.lock).write_owned().await
    }
}

/// An owned send permission, released on drop.
#[derive(Debug)]
pub struct ActiveQuerySendGuard {
    _guard: OwnedRwLockReadGuard<()>,
}

#[cfg(test)]
mod tests {
    use futures::poll;

    use super::{ActiveQuerySendGate, ActiveQuerySendGuard};

    #[tokio::test]
    async fn clones_share_the_gate_and_waiting_writers_precede_new_readers() {
        fn owned_send<T: Send + 'static>() {}
        owned_send::<ActiveQuerySendGuard>();
        let gate = ActiveQuerySendGate::default();
        let clone = gate.clone();
        let first = gate.read().await;
        let writer = clone.write();
        tokio::pin!(writer);
        assert!(poll!(&mut writer).is_pending());
        let late = gate.read();
        tokio::pin!(late);
        assert!(poll!(&mut late).is_pending());
        drop(first);
        let writer = writer.await;
        assert!(poll!(&mut late).is_pending());
        drop(writer);
        drop(late.await);
    }
}
