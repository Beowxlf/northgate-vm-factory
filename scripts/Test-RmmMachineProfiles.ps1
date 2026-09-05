# Source profile validation only. This file performs no host operation.
function Assert-RmmMachineProfiles {
    param([Parameter(Mandatory)][object[]]$Manifests)
    $expected = @(
        @('NG-VM-022','NG-RMM-CP01','debian-12.12-amd64-netinst','rmm-linux-gen2-vtpm','persistent-rmm-protected','debian12-rmm-server','rmm-server-protected',4,4096,8192,8192,80),
        @('NG-VM-023','NG-RMM-CAN01','debian-12.12-amd64-netinst','linux-gen2','lab-ephemeral-f','debian12-rmm-canary','rmm-canary-disposable',2,2048,2048,4096,40),
        @('NG-VM-024','NG-RMM-WIN01','windows-11-25h2-english-x64','windows-gen2','lab-ephemeral-f','windows11-disposable-canary','none-canary',2,4096,4096,8192,80)
    )
    if ($Manifests.Count -ne 3) { throw 'RMM requires exactly three machine profiles.' }
    foreach ($entry in $expected) {
        $matches = @($Manifests | Where-Object { $_.metadata.assetId -ceq $entry[0] })
        if ($matches.Count -ne 1) { throw 'RMM asset identity mismatch.' }
        $vm=$matches[0]; $spec=$vm.spec; $memory=$spec.compute.memory
        $actual=@($vm.metadata.assetId,$vm.metadata.name,$spec.imageRef,$spec.firmwareProfileRef,
            $spec.storage.profileRef,$spec.bootstrapProfileRef,$spec.recoveryProfileRef,
            $spec.compute.processors,$memory.minimumMiB,$memory.startupMiB,$memory.maximumMiB,$spec.storage.osDiskGiB)
        if (($actual -join '|') -cne ($entry -join '|')) { throw 'RMM machine envelope or profile binding mismatch.' }
        if ($spec.network.profileRef -cne 'business-apps' -or $memory.mode -cne 'dynamic' -or
            $spec.desiredPowerState -cne 'off' -or $spec.destroyProtection -ne $true -or
            $spec.generation -ne 2 -or $spec.intent -cne 'create' -or $vm.metadata.environment -cne 'lab') {
            throw 'RMM shared lab topology or creation protection mismatch.'
        }
        $disks=@()
        if ($spec.storage.PSObject.Properties['dataDisks']) { $disks=@($spec.storage.dataDisks) }
        if ($entry[0] -ceq 'NG-VM-022') {
            if ($disks.Count -ne 1 -or $disks[0].id -cne 'service-data' -or $disks[0].sizeGiB -ne 100 -or
                @($vm.metadata.dependencies).Count -ne 0) { throw 'RMM server disk or dependency mismatch.' }
        } elseif ($disks.Count -ne 0 -or (@($vm.metadata.dependencies) -join '|') -cne 'NG-VM-022') {
            throw 'RMM endpoint disk or dependency mismatch.'
        }
    }
}
