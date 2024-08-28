# Releases

## Schedule

The release schedule for this project is ad-hoc. Given the pre-1.0 status of the project we do not have a fixed release cadence. However if a vulnerability is discovered we will respond in accordance with our [security policy](https://github.com/cert-manager/community/blob/main/SECURITY.md) and this response may include a release.

## Process

There is a semi-automated release process for this project. When you create a Git tag with a tagname that has a `v` prefix and push it to GitHub it will trigger the [release workflow].

The release process for this repo is documented below:

1. Create a tag for the new release:
    ```sh
   export VERSION=v0.6.0-alpha.0
   git tag --annotate --message="Release ${VERSION}" "${VERSION}"
   git push origin "${VERSION}"
   ```
2. A GitHub action will see the new tag and do the following:
    - Build and publish any container images
    - Build and publish the Helm chart
    - Create a draft GitHub release
    - Upload the Helm chart tarball to the GitHub release
3. Visit the [releases page], edit the draft release, click "Generate release notes", then edit the notes to add the following to the top
    ```
    openshift-routes provides OpenShift Route support for cert-manager
    ```
4. Publish the release.

## Artifacts

This repo will produce the following artifacts each release. For documentation on how those artifacts are produced see the "Process" section.

- *Container Image* - Container image for openshift-routes is published to `ghcr.io/cert-manager/cert-manager-openshift-routes:vX.Y.Z`. 
- *Helm chart* - An official Helm chart is maintained within this repo and published to `ghcr.io/cert-manager/charts/openshift-routes:X.Y.Z`. 

[release workflow]: https://github.com/cert-manager/openshift-routes/actions/workflows/release.yaml
[releases page]: https://github.com/cert-manager/openshift-routes/releases