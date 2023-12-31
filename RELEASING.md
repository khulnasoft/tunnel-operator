# Releasing

1. Checkout your fork and make sure it's up-to-date with the `upstream`

   ```console
   $ git remote -v
   origin     git@github.com:<your account>/tunnel-operator.git (fetch)
   origin     git@github.com:<your account>/tunnel-operator.git (push)
   upstream   git@github.com/khulnasoft/tunnel-operator.git (fetch)
   upstream   git@github.com/khulnasoft/tunnel-operator.git (push)
   ```

   ```
   git pull -r
   git fetch upstream
   git merge upstream/main
   git push
   ```

2. Prepare release by creating the PR with the following changes
   1. In [`deploy/helm/Chart.yaml`]
      1. Update the `version` property
      2. Update the `appVersion` property
   2. Update the `app.kubernetes.io/version` labels in the following files:
      1. [`deploy/static/namespace.yaml`]
      2. [`deploy/helm/templates/specs/nsa-1.0.yaml`]
   3. Update static resources from Helm chart by running the make target:

      ```
      make manifests
      ```

   4. In [`mkdocs.yml`]
      1. Update the `extra.var.prev_git_tag` property
      2. Update the `extra.var.chart_version` property
3. Review and merge the PR (make sure all tests are passing)
4. Update your fork again

   ```
   git pull -r
   git fetch upstream
   git merge upstream/main
   git push
   ```

5. Create an annotated git tag and push it to the `upstream`. This will trigger the [`.github/workflows/release.yaml`] workflow

   ```
   git tag -v0.16.0-rc -m 'Release v0.16.0-rc'
   git push upstream v0.16.0-rc
   ```

6. Verify that the `release` workflow has built and published the following artifacts
   1. Tunnel-operator container images published to DockerHub
       `docker.io/khulnasoft/tunnel-operator:0.16.0-rc`
   2. Tunnel-operator container images published to Amazon ECR Public Gallery
       `public.ecr.aws/khulnasoft/tunnel-operator:0.16.0-rc`
   2. Tunnel-operator container images published to GitHub Container Registry
       `ghcr.io/khulnasoft/tunnel-operator:0.16.0-rc`
7. Publish docs on <https://khulnasoft.github.io/tunnel-operator/> by manually triggering the [`.github/workflows/publish-docs.yaml`] workflow
8. Submit tunnel-operator Operator to OperatorHub and ArtifactHUB by opening the PR to the <https://github.com/k8s-operatorhub/community-operators> repository.

[`deploy/helm/Chart.yaml`]: ./deploy/helm/Chart.yaml
[`deploy/static/namespace.yaml`]: ./deploy/static/namespace.yaml
[`deploy/helm/templates/specs/nsa-1.0.yaml`]: ./deploy/helm/templates/specs/nsa-1.0.yaml
[`mkdocs.yml`]: ./mkdocs.yml
[`.github/workflows/release.yaml`]: ./.github/workflows/release.yaml
[`.github/workflows/publish-docs.yaml`]: ./.github/workflows/publish-docs.yaml
