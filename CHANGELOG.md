# Change Log
All notable changes to this project will be documented in this file.

## [1.2.3]

### Added

- None

### Changed

- None

### Fixed

- None

### Deleted

- None

## [v5.0.0]

### Added

- Add integration test module docs ([#835](https://github.com/wazuh/wazuh-virtual-machines/pull/835))
- Add purpose input to the build ami workflow ([#773](https://github.com/wazuh/wazuh-virtual-machines/pull/773))
- Added download urls for Wazuh OVA file. ([#758](https://github.com/wazuh/wazuh-virtual-machines/pull/758))
- Add open and reopened types for pull requests trigger in check_unit_tests workflow ([#759](https://github.com/wazuh/wazuh-virtual-machines/pull/759))
- Added updating os.yml with the latest stage AMIs ([#752](https://github.com/wazuh/wazuh-virtual-machines/pull/752))
- Added RecommendedInstanceType to the AMI builds ([#756](https://github.com/wazuh/wazuh-virtual-machines/pull/756))
- Added identifier to OVA BOX sha512 URI ([#701](https://github.com/wazuh/wazuh-virtual-machines/pull/701))
- Added 5.x bumper revert changes ([#684](https://github.com/wazuh/wazuh-virtual-machines/pull/684))
- Added set-as-main option to repository bumper. ([#663](https://github.com/wazuh/wazuh-virtual-machines/pull/663))
- Add step to share AMI with the wazuh-dev and xdrsiem-dev accounts ([#650](https://github.com/wazuh/wazuh-virtual-machines/pull/650))
- Environment selection for local OVA builds and AL2023 box integration ([#633](https://github.com/wazuh/wazuh-virtual-machines/pull/633))
- Update documentation adding the Wazuh Agent information ([#611](https://github.com/wazuh/wazuh-virtual-machines/pull/611))
- Ensure the wazuh agent is stopped in the AMI customization process ([#608](https://github.com/wazuh/wazuh-virtual-machines/pull/608))
- Add agent clean up to the AMI post configurer module ([#607](https://github.com/wazuh/wazuh-virtual-machines/pull/607))
- Fix file name convetion ([#604](https://github.com/wazuh/wazuh-virtual-machines/pull/604))
- Add agent configuration process in core configurer ([#601](https://github.com/wazuh/wazuh-virtual-machines/pull/601))
- Add the wazuh agent installation in the provisioner module. ([#602](https://github.com/wazuh/wazuh-virtual-machines/pull/602))
- Add documentation for local ova build ([#562](https://github.com/wazuh/wazuh-virtual-machines/pull/562))
- Add the installation assistant tools revision in the generate presigned urls script ([#531](https://github.com/wazuh/wazuh-virtual-machines/pull/531))
- Added debug mode to customizer script for AMI. ([#513](https://github.com/wazuh/wazuh-virtual-machines/pull/513))

### Changed

- Change file and workflow names for PR revamp. ([#813](https://github.com/wazuh/wazuh-virtual-machines/pull/813))
- Changed runners to AWS CodeBuild for main branch ([#820](https://github.com/wazuh/wazuh-virtual-machines/pull/820))
- Changed the delete of Wazuh indexes process for OVA and AMI. ([#781](https://github.com/wazuh/wazuh-virtual-machines/pull/781))
- Change the destination path of the artifact_urls file for pre-release and prod environments ([#698](https://github.com/wazuh/wazuh-virtual-machines/pull/698))
- Changed OVA and AMI deployment requirements and documentation ([#694](https://github.com/wazuh/wazuh-virtual-machines/pull/694))
- Reverted PR 641. ([#649](https://github.com/wazuh/wazuh-virtual-machines/pull/649))
- Fix manager certificates ownership ([#648](https://github.com/wazuh/wazuh-virtual-machines/pull/648))
- Change artifact suffix and prod and pre-prod urls ([#640](https://github.com/wazuh/wazuh-virtual-machines/pull/640))
- Change password tool to passwords tool (add a 's') ([#637](https://github.com/wazuh/wazuh-virtual-machines/pull/637))
- Updated wazuh-virtual-machines documentation config and tooling versions to meet new standards. ([#631](https://github.com/wazuh/wazuh-virtual-machines/pull/631))
- Decoupled ova base instance deletion from the ova build workflow ([#619](https://github.com/wazuh/wazuh-virtual-machines/pull/619))
- Update artifact generation jobs to use wz-linux dedicated runner group ([#621](https://github.com/wazuh/wazuh-virtual-machines/pull/621))
- Adapt workflows to support the new dev artifact urls signing centralized script ([#614](https://github.com/wazuh/wazuh-virtual-machines/pull/614))
- Updated ova post configurer with agent/manager separation. ([#612](https://github.com/wazuh/wazuh-virtual-machines/pull/612))
- Change server references to manager due to breaking changes ([#613](https://github.com/wazuh/wazuh-virtual-machines/pull/613))
- Add WF to execute PR Check with build and test OVA and AMI ([#583](https://github.com/wazuh/wazuh-virtual-machines/pull/583))
- Add WF to execute PR Check with build and test OVA and AMI ([#594](https://github.com/wazuh/wazuh-virtual-machines/pull/594))
- Add WF to execute PR Check with build and test OVA and AMI ([#598](https://github.com/wazuh/wazuh-virtual-machines/pull/598))
- Add WF to execute PR Check with build and test OVA and AMI ([#597](https://github.com/wazuh/wazuh-virtual-machines/pull/597))
- Add WF to execute PR Check with build and test OVA and AMI ([#593](https://github.com/wazuh/wazuh-virtual-machines/pull/593))
- Add WF to execute PR Check with build and test OVA and AMI ([#591](https://github.com/wazuh/wazuh-virtual-machines/pull/591))
- Change manager /var/ossec/ references to /var/wazuh-manager/ ([#588](https://github.com/wazuh/wazuh-virtual-machines/pull/588))
- Adapt the integration test module ([#555](https://github.com/wazuh/wazuh-virtual-machines/pull/555))
- Remove latest AMI creation and add informative tags to new AMIs ([#563](https://github.com/wazuh/wazuh-virtual-machines/pull/563))
- Change URL sign expiration time and add debug messages ([#553](https://github.com/wazuh/wazuh-virtual-machines/pull/553))
- Add suport to is_stage procedure and tagging with commit and latest ([#529](https://github.com/wazuh/wazuh-virtual-machines/pull/529))
- Change passwords update process in AMI build ([#530](https://github.com/wazuh/wazuh-virtual-machines/pull/530))
- Wazuh AMI Documentation updated with ARM support. ([#515](https://github.com/wazuh/wazuh-virtual-machines/pull/515))
- OVA composite names update ([#510](https://github.com/wazuh/wazuh-virtual-machines/pull/510))
- Adapted Wazuh AMI generation code for ARM64 support. ([#507](https://github.com/wazuh/wazuh-virtual-machines/pull/507))
- Change signing script and rework AMI and OVA workflow ([#472](https://github.com/wazuh/wazuh-virtual-machines/pull/472))
- Add password-tool to the AMI configuration process ([#473](https://github.com/wazuh/wazuh-virtual-machines/pull/473))
- Update AWS S3 OVA path ([#465](https://github.com/wazuh/wazuh-virtual-machines/pull/465))
- Update certificate handling and configuration ([#468](https://github.com/wazuh/wazuh-virtual-machines/pull/468))
- Update indexes deleted in OVA and AMI builds. ([#459](https://github.com/wazuh/wazuh-virtual-machines/pull/459))

### Fixed

- Fixed error in ova and ami checks. ([#792](https://github.com/wazuh/wazuh-virtual-machines/pull/792))
- Fix AMI ARM build failing when fetching the manager package ([#745](https://github.com/wazuh/wazuh-virtual-machines/pull/745))
- Added merge step in bumper workflow. ([#671](https://github.com/wazuh/wazuh-virtual-machines/pull/671))
- Fixed Wazuh ami default ssh port. ([#641](https://github.com/wazuh/wazuh-virtual-machines/pull/641))
- Replace incorrect dashboard API check function in AMI customizer ([#636](https://github.com/wazuh/wazuh-virtual-machines/pull/636))
- Fix check vulnerabilities ([#609](https://github.com/wazuh/wazuh-virtual-machines/pull/609))
- Fix ami `pre configurer` tests([#595](https://github.com/wazuh/wazuh-virtual-machines/pull/595))
- Add arch suffix to the allocator artifact in the builder AMI workflow ([#556](https://github.com/wazuh/wazuh-virtual-machines/pull/556))
- Updated Amazon linux upgrade method. ([#540](https://github.com/wazuh/wazuh-virtual-machines/pull/540))
- Fix cloud-init leftovers and network configuration in OVA build for 5.0 ([#534](https://github.com/wazuh/wazuh-virtual-machines/pull/534))
- Fix vagrant up inconsistencies at the renewed OVA build process ([#474](https://github.com/wazuh/wazuh-virtual-machines/pull/474))
- Fix vagrant up inconsistencies at the start. ([#435](https://github.com/wazuh/wazuh-virtual-machines/pull/435))

### Deleted

- Removed OVA and AMI deprecated files. ([#554](https://github.com/wazuh/wazuh-virtual-machines/pull/554))

## Prior version

- []()