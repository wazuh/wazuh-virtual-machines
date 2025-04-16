# Change Log
All notable changes to this project will be documented in this file.

## [5.0.0]

### Added

- Added AMI test framework ([#266](https://github.com/wazuh/wazuh-virtual-machines/pull/266))
- Update the OVA creation workflow using the new python modules ([#262](https://github.com/wazuh/wazuh-virtual-machines/pull/262))
- Update the AMI creation workflow using the new python modules ([#260](https://github.com/wazuh/wazuh-virtual-machines/pull/260))
- Create the AMI PostConfigure submodule ([#255](https://github.com/wazuh/wazuh-virtual-machines/pull/255))
- Create the OVA PostConfigurer module ([#249](https://github.com/wazuh/wazuh-virtual-machines/pull/249))
- Add the AMI pre_configurer submodule ([#242](https://github.com/wazuh/wazuh-virtual-machines/pull/242))
- Create the PreConfigurer for the OVA ([#241](https://github.com/wazuh/wazuh-virtual-machines/pull/241))
- Create the Core Configurer Module for OVA and AMI ([#236](https://github.com/wazuh/wazuh-virtual-machines/pull/236))
- Create the Provisioner Module for OVA and AMI ([#224](https://github.com/wazuh/wazuh-virtual-machines/pull/224))

### Changed

- Updated VERSION file to the new standard. ([#213](https://github.com/wazuh/wazuh-virtual-machines/pull/213))

### Fixed

- None

### Deleted

- Removed VERSION file from main branch. ([#221](https://github.com/wazuh/wazuh-virtual-machines/pull/221))

## [4.10.2]

### Added

- None

### Changed

- None

### Fixed

- None

### Deleted

- None

## [4.10.1]

### Added

- None

### Changed

- Improvements to AMI customization script. ([#98](https://github.com/wazuh/wazuh-virtual-machines/pull/98))

### Fixed

- None

### Deleted

- None

## [4.10.0]

### Added

- Added echo of the OVA URI ([#84](https://github.com/wazuh/wazuh-virtual-machines/pull/84))
- Add security policy ([#46](https://github.com/wazuh/wazuh-virtual-machines/pull/46))
- Add packages_builder_ami workflow ([#40](https://github.com/wazuh/wazuh-virtual-machines/pull/40))
- Added builder_OVA workflow ([#32](https://github.com/wazuh/wazuh-virtual-machines/pull/32))
- Added packages_builder_ami workflow header ([#31](https://github.com/wazuh/wazuh-virtual-machines/pull/31))
- Added the OVA to the wazuh-virtual-machines repository without changes ([#30](https://github.com/wazuh/wazuh-virtual-machines/pull/30)) - (OVA)

### Changed

- Changed the SSH port of the AMI to 22 ([#83](https://github.com/wazuh/wazuh-virtual-machines/pull/83))
- Migrated certificates and passwords changes for AMI. ([#73](https://github.com/wazuh/wazuh-virtual-machines/pull/73))
- Add a new input for wazuh-virtual-machines reference to the OVA and AMI workflows ([#70](https://github.com/wazuh/wazuh-virtual-machines/pull/70))
- Adapted repository selection in OVA generation ([#58](https://github.com/wazuh/wazuh-virtual-machines/pull/58))
- Modify the AMI GHA workflow with the new Installation Assistant logic ([#55](https://github.com/wazuh/wazuh-virtual-machines/pull/55))
- Migrated Build OVA pipeline from Jenkins to GHA Workflow ([#44](https://github.com/wazuh/wazuh-virtual-machines/pull/44))
- Migrated the OVA construction files to the wazuh-virtual-machines repository ([#29](https://github.com/wazuh/wazuh-virtual-machines/pull/29)) - (OVA)

### Fixed

- Add validation in the generate_ova.sh file when use tag instead a branch reference ([#100](https://github.com/wazuh/wazuh-virtual-machines/pull/100))
- Added ova extension to the sha file and change S3 directory from OVA to ova ([#96](https://github.com/wazuh/wazuh-virtual-machines/pull/96))
- Added # to the Port 22 configuration in the AMI instance ([#97](https://github.com/wazuh/wazuh-virtual-machines/pull/97))
- Changed GitHub Runner version to fix Python error ([#82](https://github.com/wazuh/wazuh-virtual-machines/pull/82))
- Deleted dashboard logs cleanup in OVA local build ([#57](https://github.com/wazuh/wazuh-virtual-machines/pull/57))
- Fix typos and add news inputs in the AMI workflow header ([#35](https://github.com/wazuh/wazuh-virtual-machines/pull/35))

### Deleted

- None

## [4.9.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.9.2

## [4.9.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.9.1

## [4.9.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.9.0

## [4.8.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.8.2

## [4.8.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.8.1

## [4.8.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.8.0

## [4.7.5]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.5

## [4.7.4]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.4

## [4.7.3]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.3

## [4.7.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.2

## [4.7.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.1

## [v4.7.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.7.0

## [v4.6.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.6.0

## [v4.5.4]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.5.4

## [v4.5.3]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.5.3

## [v4.5.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.5.2

## [v4.5.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.5.1

## [v4.5.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.5.0

## [v4.4.5]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.5

## [v4.4.4]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.4

## [v4.4.3]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.3

## [v4.4.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.2

## [v4.3.11]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.11

## [v4.4.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.1

## [v4.4.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.4.0

## [v4.3.10]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.10

## [v4.3.9]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.9

## [v4.3.8]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.8

## [v4.3.7]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.7

## [v4.3.6]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.6

## [v4.3.5]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.5

## [v4.3.4]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.4

## [v4.3.3]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.3

## [v4.3.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.2

## [v4.2.7]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.7

## [v4.3.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.1

## [v4.3.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.3.0

## [v4.2.6]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.6

## [v4.2.5]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.5

## [v4.2.4]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.4

## [v4.2.3]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.3

## [v4.2.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.2

## [v4.2.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.1

## [v4.2.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.2.0

## [v4.1.5]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.1.5

## [v4.1.4]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.1.4

## [v4.1.3]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.1.3

## [v4.1.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.1.2

## [v4.1.1]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.1.1

## [v4.0.2]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.0.2

## [v4.0.0]

- https://github.com/wazuh/wazuh-packages/releases/tag/v4.0.0
