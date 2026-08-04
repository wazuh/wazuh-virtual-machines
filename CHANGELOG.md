## [v5.0.0]

### Added


| Issue | Comment |
| - | - |
| [#807](https://github.com/wazuh/wazuh-virtual-machines/issues/807) | Add bump-issue-link support for Revert Stage Bump in wazuh-virtual-machines |
| [#835](https://github.com/wazuh/wazuh-virtual-machines/pull/835) | Add integration test module docs |
| [#773](https://github.com/wazuh/wazuh-virtual-machines/pull/773) | Add purpose input to the build ami workflow |
| [#734](https://github.com/wazuh/wazuh-virtual-machines/issues/734) | Update OVA documentation to include the download URL |
| [#759](https://github.com/wazuh/wazuh-virtual-machines/pull/759) | Add open and reopened types for pull requests trigger in check_unit_tests workflow |
| [#716](https://github.com/wazuh/wazuh-virtual-machines/issues/716) | Update os.yml file with the latest stage AMIs |
| [#755](https://github.com/wazuh/wazuh-virtual-machines/issues/755) | Add a new tag attribute to the AMI builder process |
| [#691](https://github.com/wazuh/wazuh-virtual-machines/issues/691) | Change the key of the generated `.box` sha512 URI in OVA generate workflow |
| [#673](https://github.com/wazuh/wazuh-virtual-machines/issues/673) | Support Revert bump functionality in wazuh-virtual-machines |
| [#642](https://github.com/wazuh/wazuh-virtual-machines/issues/642) | Add `--set-as-main` flag support to repository bumper — `wazuh-virtual-machines` |
| [#427](https://github.com/wazuh/wazuh-virtual-machines/issues/427) | Share AMI with `wazuh-dev` and `xdrsiem-dev` AWS accounts |
| [#628](https://github.com/wazuh/wazuh-virtual-machines/issues/628) | Environment selection for local OVA builds and AL2023 box integration |
| [#571](https://github.com/wazuh/wazuh-virtual-machines/issues/571) | Development - Separate Agent/Manager - VMs - Update documentation |
| [#570](https://github.com/wazuh/wazuh-virtual-machines/issues/570) | Development - Separate Agent/Manager - VMs - Ensure the Wazuh agent is stopped in the AMI customization process |
| [#568](https://github.com/wazuh/wazuh-virtual-machines/issues/568) | Development - Separate Agent/Manager - VMs - Add Wazuh agent clean up in the AMI `post configurer` module |
| [#596](https://github.com/wazuh/wazuh-virtual-machines/issues/596) | URL presigned file -  Verify that the OVA and AMI packages comply with the development naming convention. |
| [#567](https://github.com/wazuh/wazuh-virtual-machines/issues/567) | Development - Separate Agent/Manager - VMs - Configure the Wazuh agent in the `core configurer` module |
| [#566](https://github.com/wazuh/wazuh-virtual-machines/issues/566) | Development - Separate Agent/Manager - VMs - Add the Wazuh agent installation in the provisioner module |
| [#545](https://github.com/wazuh/wazuh-virtual-machines/issues/545) | Update Ova documentation with local build |
| [#531](https://github.com/wazuh/wazuh-virtual-machines/pull/531) | Add the installation assistant tools revision in the generate presigned urls script |
| [#504](https://github.com/wazuh/wazuh-virtual-machines/issues/504) | ARM AMI - Ensure functional parity between ARM64 and AMD64 AMIs |

### Changed


| Issue | Comment |
| - | - |
| [#883](https://github.com/wazuh/wazuh-virtual-machines/issues/883) | Error on AMI and OVA Build |
| [#872](https://github.com/wazuh/wazuh-virtual-machines/issues/872) | Update deployment for Wazuh Indexer 5.0.0 RBAC (VMs) |
| [#859](https://github.com/wazuh/wazuh-virtual-machines/issues/859) | Modify the Wazuh indexer heap size |
| [#874](https://github.com/wazuh/wazuh-virtual-machines/pull/874) | Add new WF for changelog check |
| [#844](https://github.com/wazuh/wazuh-virtual-machines/pull/844) | Change upload and download methods |
| [#857](https://github.com/wazuh/wazuh-virtual-machines/issues/857) | Set authd password in agents installation |
| [#813](https://github.com/wazuh/wazuh-virtual-machines/pull/813) | Change file and workflow names for PR revamp. |
| [#820](https://github.com/wazuh/wazuh-virtual-machines/pull/820) | Changed runners to AWS CodeBuild for main branch |
| [#779](https://github.com/wazuh/wazuh-virtual-machines/issues/779) | Update the deleted indexes in OVA and AMI builds |
| [#679](https://github.com/wazuh/wazuh-virtual-machines/issues/679) | Change the destination path of the artifact_urls file in wazuh-virtual-machines |
| [#688](https://github.com/wazuh/wazuh-virtual-machines/issues/688) | Update the hardware required for OVA and AMI 5.0.0 |
| [#649](https://github.com/wazuh/wazuh-virtual-machines/pull/649) | Reverted PR 641. |
| [#647](https://github.com/wazuh/wazuh-virtual-machines/issues/647) | Virtual machines - Ensure correct Wazuh manager certificates ownership |
| [#640](https://github.com/wazuh/wazuh-virtual-machines/pull/640) | Change artifact suffix and prod and pre-prod urls |
| [#635](https://github.com/wazuh/wazuh-virtual-machines/issues/635) | Wazuh virtual machines - Review and update the passwords tool's naming conventions |
| [#631](https://github.com/wazuh/wazuh-virtual-machines/pull/631) | Updated wazuh-virtual-machines documentation config and tooling versions to meet new standards. |
| [#584](https://github.com/wazuh/wazuh-virtual-machines/issues/584) | Decouple EC2 bare metal termination from GHA workflow in OVA build and monitor termination failures via EventBridge |
| [#621](https://github.com/wazuh/wazuh-virtual-machines/pull/621) | Update artifact generation jobs to use wz-linux dedicated runner group |
| [#599](https://github.com/wazuh/wazuh-virtual-machines/issues/599) | URL presigned file - Update the Wazuh virtual machines arctifact creation workflows |
| [#569](https://github.com/wazuh/wazuh-virtual-machines/issues/569) | Development - Separate Agent/Manager - VMs - Add Wazuh agent clean up in the OVA `post configurer` module |
| [#610](https://github.com/wazuh/wazuh-virtual-machines/issues/610) | Wazuh Manager/agent Separation - Breaking changes summary |
| [#578](https://github.com/wazuh/wazuh-virtual-machines/issues/578) | Addapt Builder OVA and AMI to execute test WF |
| [#564](https://github.com/wazuh/wazuh-virtual-machines/issues/564) | Development - Separate Agent/Manager - VMs - Update the Wazuh Manager path references to `/var/wazuh-manager/` |
| [#548](https://github.com/wazuh/wazuh-virtual-machines/issues/548) | Adapt the integration test module |
| [#549](https://github.com/wazuh/wazuh-virtual-machines/issues/549) | Duplicate AMI name in CreateImage in AWS EC2 |
| [#553](https://github.com/wazuh/wazuh-virtual-machines/pull/553) | Change URL sign expiration time and add debug messages |
| [#526](https://github.com/wazuh/wazuh-virtual-machines/issues/526) | Update the OVA and AMI workflow upload a latest arctifact in case of is_stage == false |
| [#516](https://github.com/wazuh/wazuh-virtual-machines/issues/516) | Adapt password change in AMI build to new restrictions |
| [#506](https://github.com/wazuh/wazuh-virtual-machines/issues/506) | ARM AMI - Update Wazuh AMI guides for ARM64 support |
| [#510](https://github.com/wazuh/wazuh-virtual-machines/pull/510) | OVA composite names update |
| [#503](https://github.com/wazuh/wazuh-virtual-machines/issues/503) | ARM AMI - Adapt Wazuh AMI generation code for ARM64 support |
| [#451](https://github.com/wazuh/wazuh-virtual-machines/issues/451) | Development - DevOps 5.0 adaptation - AMI & OVA - Update the path to the development URL file in the build workflows |
| [#450](https://github.com/wazuh/wazuh-virtual-machines/issues/450) | Development - DevOps 5.0 adaptation - AMI - Password tool development |
| [#456](https://github.com/wazuh/wazuh-virtual-machines/issues/456) | Development - DevOps 5.0 adaptation - OVA - Adapt the uploading AWS S3 path for the OVA |
| [#448](https://github.com/wazuh/wazuh-virtual-machines/issues/448) | Development - DevOps 5.0 adaptation - AMI & OVA - Update certificates in the core configurer |
| [#449](https://github.com/wazuh/wazuh-virtual-machines/issues/449) | Development - DevOps 5.0 adaptation - AMI & OVA - Update indexer indices to remove |

### Removed


| Issue | Comment |
| - | - |
| [#544](https://github.com/wazuh/wazuh-virtual-machines/issues/544) | Removed obsolete OVA and AMI creation methods |

### Fixed


| Issue | Comment |
| - | - |
- Test entry with wrong format (issue 9999)
| This is not a valid entry format | Missing issue link entirely |
| [#896](https://github.com/wazuh/wazuh-docker/issues/896) | Fixed changelog check workflow to accept Prior versions entries |
| [#856](https://github.com/wazuh/wazuh-virtual-machines/issues/856) | Unexpected failure when repository bump is executed and no changes are made |
| [#826](https://github.com/wazuh/wazuh-virtual-machines/issues/826) | Bumper script issue when the tag is set to false |
| [#787](https://github.com/wazuh/wazuh-virtual-machines/issues/787) | Error in OVA and AMI checks |
| [#744](https://github.com/wazuh/wazuh-virtual-machines/issues/744) | The AMI ARM build is failing when it fetches the manager package |
| [#670](https://github.com/wazuh/wazuh-virtual-machines/issues/670) | Bump PR not merged in either step despite workflow reporting success |
| [#634](https://github.com/wazuh/wazuh-virtual-machines/issues/634) | Unreachable AMI via SSH connection for AWS |
| [#609](https://github.com/wazuh/wazuh-virtual-machines/pull/609) | Fix check vulnerabilities |
| [#585](https://github.com/wazuh/wazuh-virtual-machines/issues/585) | Fix failing AMI `pre-configurer` tests |
| [#550](https://github.com/wazuh/wazuh-virtual-machines/issues/550) | AMI build upload GitHub workflow artifact fails due to duplicated name |
| [#539](https://github.com/wazuh/wazuh-virtual-machines/issues/539) | Failure when building AMI from the main branch |
| [#519](https://github.com/wazuh/wazuh-virtual-machines/issues/519) | Clean OVA files related to Cloud Init and Vagrant |
| [#437](https://github.com/wazuh/wazuh-virtual-machines/issues/437) | Addapt OVA generation fixes while generate vagrant resources |
| [#426](https://github.com/wazuh/wazuh-virtual-machines/issues/426) | OVA generation failed while creating the Vagrant resource |

## Prior versions

- []()
