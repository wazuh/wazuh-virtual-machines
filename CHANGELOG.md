# Change Log
All notable changes to this project will be documented in this file.

## [6.0.0]

### Added

- Add wget as a package dependency ([#309](https://github.com/wazuh/wazuh-virtual-machines/pull/309))
- Create build process for local ova and fix certificates default path for Wazuh Server ([#299](https://github.com/wazuh/wazuh-virtual-machines/pull/299))
- Added OVA test to VM framework test module ([#276](https://github.com/wazuh/wazuh-virtual-machines/pull/276))
- Add OVA documentation ([#275](https://github.com/wazuh/wazuh-virtual-machines/pull/275))
- Add AMI and global modules ref documentation ([#272](https://github.com/wazuh/wazuh-virtual-machines/pull/272))
- Add AMI ref documentation ([#269](https://github.com/wazuh/wazuh-virtual-machines/pull/269))
- Add AMI dev documentation ([#267](https://github.com/wazuh/wazuh-virtual-machines/pull/267))
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

- Update bucket references to corresponding new resources ([#358](https://github.com/wazuh/wazuh-virtual-machines/pull/358))
- Updated VERSION file to the new standard. ([#213](https://github.com/wazuh/wazuh-virtual-machines/pull/213))

### Fixed

-
Fix vagrant up inconsistencies at the start. ([#436](https://github.com/wazuh/wazuh-virtual-machines/pull/434365))
- Fixed SHA file reference ([#365](https://github.com/wazuh/wazuh-virtual-machines/pull/365))
- Fixed several OVA workflow and creation process errors ([#270](https://github.com/wazuh/wazuh-virtual-machines/pull/270))

### Deleted

- Removed VERSION file from main branch. ([#221](https://github.com/wazuh/wazuh-virtual-machines/pull/221))

## [5.0.0]

### Added

- None

### Changed

- None

### Fixed

- None

### Deleted

- None

## [4.13.0]

### Added

- Integrate bumper script via GitHub action. ([#331](https://github.com/wazuh/wazuh-virtual-machines/pull/331))
- Added repository_bumper.sh script. ([#271](https://github.com/wazuh/wazuh-virtual-machines/pull/271))

### Changed

- Updated the regular expression for the new indexes ([#240](https://github.com/wazuh/wazuh-virtual-machines/pull/240))

### Fixed

- Fix obtaining the tag in case the INSTALLATION_ASSISTANT_BRANCH variable contains the HEAD ([#239](https://github.com/wazuh/wazuh-virtual-machines/pull/239))

### Deleted

- Remove default virtual-machines reference version from workflow ([#237](https://github.com/wazuh/wazuh-virtual-machines/pull/237))

## [4.10.2]

### Added

- None

### Changed

- None

### Fixed

- None

### Deleted

- None

## [4.11.1]

### Added

- None

### Changed

- None

### Fixed

- None

### Deleted

- None

## [4.11.0]

### Added

- None

### Changed

- Reworked the OVA workflow, creation process and upgraded base OS. ([#170](https://github.com/wazuh/wazuh-virtual-machines/pull/170))
- Change OS base for Wazuh AMI to Amazon Linux 2023. ([#150](https://github.com/wazuh/wazuh-virtual-machines/pull/150))
- Added venv to AMI and OVA workflows. ([#112](https://github.com/wazuh/wazuh-virtual-machines/pull/112))
- Improvements to AMI customization script. ([#98](https://github.com/wazuh/wazuh-virtual-machines/pull/98))

### Fixed

- Fix Wazuh dashboard errors in OVA. ([#209](https://github.com/wazuh/wazuh-virtual-machines/pull/209))
- Fixed local build for OVA. ([#208](https://github.com/wazuh/wazuh-virtual-machines/pull/208))
- Fixed Wazuh Dashboard issues when the AMI boots up. ([#205](https://github.com/wazuh/wazuh-virtual-machines/pull/205))
- Fix Wazuh dashboard certificate verification failure ([#198](https://github.com/wazuh/wazuh-virtual-machines/pull/198))
- Fixed Wazuh ASCII art logo display in OVA. ([#192](https://github.com/wazuh/wazuh-virtual-machines/pull/192))
- Fixed video in grub configuration for the OVA. ([#190](https://github.com/wazuh/wazuh-virtual-machines/pull/190))
- Changed ssh config file to allow ssh while FIPS is activated. ([#184](https://github.com/wazuh/wazuh-virtual-machines/pull/184))
- Fixed Vagrant synced folder error in OVA. ([#183](https://github.com/wazuh/wazuh-virtual-machines/pull/183))
- Fix the ova workflow for stages support and AWS instance deletion. ([#175](https://github.com/wazuh/wazuh-virtual-machines/pull/176))
- Fixed the OVA workflow to add support in stages. ([#173](https://github.com/wazuh/wazuh-virtual-machines/pull/173))

### Deleted

- None

## [4.10.1]

### Added

- None

### Changed

- None

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

- Change inputs parameters in AMI and OVA workflows ([#118](https://github.com/wazuh/wazuh-virtual-machines/pull/118))
- Change ami and ova workflows input upper_case to lower_case ([#114](https://github.com/wazuh/wazuh-virtual-machines/pull/114))
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
