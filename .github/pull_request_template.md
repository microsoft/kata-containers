<!--
COMMENT BLOCKS WILL NOT BE INCLUDED IN THE PR.
Feel free to delete sections of the template which do not apply to your PR, or add additional details
-->

###### Merge Checklist  <!-- REQUIRED -->
<!-- You can set them now ([x]) or set them later using the Github UI -->
<!-- **All** boxes should be checked before merging the PR *(just tick any boxes which don't apply to this PR)* -->
- [ ] Followed patch format from upstream recommendation: https://github.com/kata-containers/community/blob/main/CONTRIBUTING.md#patch-format
  - [ ] Included a single commit in a given PR - at least unless there are related commits and each makes sense as a change on its own.
- [ ] Aware about the PR to be merged using "create a merge commit" rather than "squash and merge" (or similar)
- [ ] genPolicy only: Ensured the tool still builds on Windows
- [ ] genPolicy only: Updated sample YAMLs' policy annotations, if applicable
- [ ] The `upstream-missing` label (or `upstream-not-needed`) has been set on the PR. 

###### Summary <!-- REQUIRED -->
<!-- Quick explanation of WHAT changed and WHY. -->

###### Associated issues  <!-- optional -->
<!-- Link to Github issues if possible. -->

###### Links to CVEs  <!-- optional -->
<!-- https://nvd.nist.gov/vuln/detail/CVE-YYYY-XXXX -->

###### Test Methodology
<!-- How was this test validated? i.e. local build, pipeline build etc. -->
