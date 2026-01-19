const Scan = require('../models/Scan');

/**
 * Cleanup orphaned scans on server startup
 * Scans stuck in 'pending' or 'running' status mean the server crashed/restarted
 * These should be marked as failed since they're not actually running
 */
async function cleanupOrphanedScans() {
    try {
        console.log('[Startup] Checking for orphaned scans...');

        // Find all scans that are still marked as pending or running
        const orphanedScans = await Scan.findAll({
            where: {
                status: ['pending', 'running']
            }
        });

        if (orphanedScans.length === 0) {
            console.log('[Startup] ✅ No orphaned scans found');
            return { cleaned: 0 };
        }

        console.log(`[Startup] ⚠️  Found ${orphanedScans.length} orphaned scan(s) - marking as failed`);

        // Mark all orphaned scans as failed
        for (const scan of orphanedScans) {
            await scan.markFailed('Server was restarted while scan was in progress');
            console.log(`[Startup]   ✗ Marked scan ${scan.id} as failed (was in '${scan.status}' status)`);
        }

        console.log(`[Startup] ✅ Cleaned up ${orphanedScans.length} orphaned scan(s)`);
        return { cleaned: orphanedScans.length };

    } catch (error) {
        console.error('[Startup] ❌ Error cleaning up orphaned scans:', error);
        throw error;
    }
}

module.exports = { cleanupOrphanedScans };
