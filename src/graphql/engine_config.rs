//! The lock that serializes the writers of Unsupervised Engine configuration.

use std::sync::Arc;

use async_graphql::{Context, Result};

/// The lock that orders every writer of Unsupervised Engine configuration, one
/// per schema.
///
/// review-database's guards refuse a write that would break a reference — an
/// indicator update or removal while an engine document or a training
/// definition names it, for example — by scanning the references stored when
/// the write's transaction runs. That scan cannot see a reference a
/// concurrent transaction is creating, and the node writers
/// `NodeTable::update_with_engine_documents` (`updateNodeDraft`, `applyNode`,
/// `applyNodeDraft`) and `NodeTable::put` (`insertNode`) retry a conflicting
/// commit without re-running their caller's checks. So every writer that
/// checks or creates a reference to a source, a model or an indicator, or
/// changes a node's customer or hostname, holds this one lock from before its
/// checks until its store write returns. Every such writer takes this lock;
/// none adds another.
///
/// Sampling-policy uses are found by such a scan too, so every writer that
/// checks the uses of a sampling policy holds it as well.
///
/// The writers that hold it are `insertIndicator`, `updateIndicator` and
/// `removeIndicator`; `insertTrainingDefinition`, `updateTrainingDefinition`,
/// `trainModel`, `cloneModel`, `removeModel` and `assignModel`;
/// `removeSamplingPolicies`, which takes the sampling policies lock after
/// it, and `assignSamplingPolicy`; and the node writes `insertNode`,
/// `updateNodeDraft`, `applyNode` and `applyNodeDraft`, the last two of which
/// also check the uses of a Time Series Generator's policies before its Data
/// Store changes. The sampling-policy and node writers release it before any
/// agent is notified.
///
/// Take it before [`get_store`](super::get_store): the store guard is a
/// `std::sync::RwLockReadGuard`, which cannot be held across the lock's
/// `.await`.
#[derive(Default)]
pub(crate) struct EngineConfigLock {
    mutex: tokio::sync::Mutex<()>,
    /// How many operations hold or wait for the lock.
    #[cfg(test)]
    users: std::sync::atomic::AtomicUsize,
}

impl EngineConfigLock {
    /// Returns how many operations hold or wait for the lock.
    #[cfg(test)]
    pub(super) fn users(&self) -> usize {
        self.users.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Takes the lock outside a request, as a test holding it off a resolver
    /// does.
    #[cfg(test)]
    pub(super) async fn hold(&self) -> EngineConfigGuard<'_> {
        let user = LockUser::new(&self.users);
        let guard = self.mutex.lock().await;
        EngineConfigGuard {
            _guard: guard,
            _user: user,
        }
    }
}

/// The guard of a held [`EngineConfigLock`].
pub(crate) struct EngineConfigGuard<'a> {
    _guard: tokio::sync::MutexGuard<'a, ()>,
    #[cfg(test)]
    _user: LockUser<'a>,
}

/// Counts an operation among the users of an [`EngineConfigLock`] from before
/// it waits for the lock until it releases it or stops waiting.
#[cfg(test)]
struct LockUser<'a>(&'a std::sync::atomic::AtomicUsize);

#[cfg(test)]
impl<'a> LockUser<'a> {
    fn new(users: &'a std::sync::atomic::AtomicUsize) -> Self {
        users.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(users)
    }
}

#[cfg(test)]
impl Drop for LockUser<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Waits for the engine configuration to be free and locks it.
///
/// # Errors
///
/// Returns an error if the schema holds no [`EngineConfigLock`].
pub(crate) async fn lock_engine_config<'a>(ctx: &Context<'a>) -> Result<EngineConfigGuard<'a>> {
    let lock = ctx.data::<Arc<EngineConfigLock>>()?;
    #[cfg(test)]
    let user = LockUser::new(&lock.users);
    let guard = lock.mutex.lock().await;
    Ok(EngineConfigGuard {
        _guard: guard,
        #[cfg(test)]
        _user: user,
    })
}
