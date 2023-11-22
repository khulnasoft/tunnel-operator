# kubectl

The Kubernetes Yaml Deployment files are available on GitHub in [https://github.com/khulnasoft/tunnel-operator](https://github.com/khulnasoft/tunnel-operator) under `/deploy/static`.

## Example - Deploy from GitHub

This will install the operator in the `tunnel-system` namespace and configure it to scan all namespaces, except `kube-system` and `tunnel-system`:

```bash
kubectl apply -f https://raw.githubusercontent.com/khulnasoft/tunnel-operator/{{ git.tag }}/deploy/static/tunnel-operator.yaml
```

To confirm that the Operator is running, check that the `tunnel-operator` Deployment in the `tunnel-system`
namespace is available and all its containers are ready:

```bash
$ kubectl get deployment -n tunnel-system
NAME                 READY   UP-TO-DATE   AVAILABLE   AGE
tunnel-operator   1/1     1            1           11m
```

If for some reason it's not ready yet, check the logs of the `tunnel-operator` Deployment for errors:

```bash
kubectl logs deployment/tunnel-operator -n tunnel-system
```

## Advanced Configuration

You can configure Tunnel-Operator to control it's behavior and adapt it to your needs. Aspects of the operator machinery are configured using environment variables on the operator Pod, while aspects of the scanning behavior are controlled by ConfigMaps and Secrets.
To learn more, please refer to the [Configuration](configuration) documentation.

## Uninstall

!!! danger
    Uninstalling the operator and deleting custom resource definitions will also delete all generated security reports.

You can uninstall the operator with the following command:

```
kubectl delete -f https://raw.githubusercontent.com/khulnasoft/tunnel-operator/{{ git.tag }}/deploy/static/tunnel-operator.yaml
```

[Settings]: ./../../settings.md
[Helm]: ./helm.md
