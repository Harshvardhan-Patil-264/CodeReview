const Scan = require('../models/Scan');

/**
 * Fix scans stuck in 'running' status
 * This happens when scans completed but weren't marked as completed
 */

async function fixStuckScans() {
    try {
        console.log('Checking for scans stuck in "running" status...');

        const stuckScans = await Scan.findAll({
            where: {
                status: 'running'
            }
        });

        if (stuckScans.length === 0) {
            console.log('✅ No stuck scans found!');
            return;
        }

        console.log(`Found ${stuckScans.length} scan(s) stuck in "running" status`);

        for (const scan of stuckScans) {
            // Check if scan has report paths (means it actually completed)
            if (scan.reportPaths && scan.reportPaths.length > 0) {
                console.log(`  ✓ Marking scan ${scan.id} as completed (has ${scan.reportPaths.length} report(s))`);
                await scan.markCompleted(scan.reportPaths, scan.duration || 0);
            } else {
                // No reports means it likely failed
                console.log(`  ✗ Marking scan ${scan.id} as failed (no reports)`);
                await scan.markFailed('Scan did not complete properly');
            }
        }

        console.log('✅ All stuck scans have been fixed!');
        process.exit(0);

    } catch (error) {
        console.error('❌ Error fixing stuck scans:', error);
        process.exit(1);
    }
}

// Run the fix
fixStuckScans();
