# Troubleshooting the Tunnel Operator

The Tunnel Operator installs several Kubernetes resources into your Kubernetes cluster.

Here are the common steps to check whether the operator is running correctly and to troubleshoot common issues.

So in addition to this section, you might want to check [issues](https://github.com/khulnasoft/tunnel/issues), [discussion forum](https://github.com/khulnasoft/tunnel/discussions), or [Slack](https://slack.khulnasoft.com) to see if someone from the community had similar problems before.

Also note that Tunnel Operator is based on existing Khulnasoft OSS project - [Starboard], and shares some of the design, principles and code with it. Existing content that relates to Starboard Operator might also be relevant for Tunnel Operator, and Starboard's [issues](https://github.com/khulnasoft/starboard/issues), [discussion forum](https://github.com/khulnasoft/starboard/discussions), or [Slack](https://slack.khulnasoft.com) might also be interesting to check.  
In some cases you might want to refer to [Starboard's Design documents](https://khulnasoft.github.io/starboard/latest/design/)

## Installation

Make sure that the latest version of the Tunnel Operator is installed. For this, have a look at the installation [options.](./helm.md)

For instance, if your are using the Helm deployment, you need to check the Helm Chart version deployed to your cluster. You can check the Helm Chart version with the following command:
```
helm list -n tunnel-system
```

## Operator Pod Not Running

The Tunnel Operator will run a pod inside your cluster. If you have followed the installation guide, you will have installed the Operator to the `tunnel-system`.

Make sure that the pod is in the `Running` status:
```
kubectl get pods -n tunnel-system
```

This is how it will look if it is running okay:

```
NAMESPACE            NAME                                         READY   STATUS    RESTARTS      AGE
tunnel-system     tunnel-operator-6c9bd97d58-hsz4g          1/1     Running   5 (19m ago)   30h
```

If the pod is in `Failed`, `Pending`, or `Unknown` check the events and the logs of the pod.

First, check the events, since they might be more descriptive of the problem. However, if the events do not give a clear reason why the pod cannot spin up, then you want to check the logs, which provide more detail.

```
kubectl describe pod <POD-NAME> -n tunnel-system
```

To check the logs, use the following command:
```
kubectl logs deployment/tunnel-operator -n tunnel-system
```

If your pod is not running, try to look for errors as they can give an indication on the problem.

If there are too many logs messages, try deleting the Tunnel pod and observe its behavior upon restarting. A new pod should spin up automatically after deleting the failed pod.

## ImagePullBackOff or ErrImagePull

Check the status of the Tunnel Operator pod running inside of your Kubernetes cluster. If the Status is ImagePullBackOff or ErrImagePull, it means that the Operator either

* tries to access the wrong image
* cannot pull the image from the registry

Make sure that you are providing the right resources upon installing the Tunnel Operator.

## CrashLoopBackOff

If your pod is in `CrashLoopBackOff`, it is likely the case that the pod cannot be scheduled on the Kubernetes node that it is trying to schedule on.
In this case, you want to investigate further whether there is an issue with the node. It could for instance be the case that the node does not have sufficient resources.

## Reconciliation Error

It could happen that the pod appears to be running normally but does not reconcile the resources inside of your Kubernetes cluster.

Check the logs for Reconciliation errors:
```
kubectl logs deployment/tunnel-operator -n tunnel-system
```

If this is the case, the Tunnel Operator likely does not have the right configurations to access your resource.

## Operator does not Create VulnerabilityReports

VulnerabilityReports are owned and controlled by the immediate Kubernetes workload. Every VulnerabilityReport of a pod is thus, linked to a [ReplicaSet.](./index.md) In case the Tunnel Operator does not create a VulnerabilityReport for your workloads, it could be that it is not monitoring the namespace that your workloads are running on.

An easy way to check this is by looking for the `ClusterRoleBinding` for the Tunnel Operator:

```
kubectl get ClusterRoleBinding | grep "tunnel-operator"
```

Alternatively, you could use the `kubectl-who-can` [plugin by Khulnasoft](https://github.com/khulnasoft/kubectl-who-can):

```console
$ kubectl who-can list vulnerabilityreports
No subjects found with permissions to list vulnerabilityreports assigned through RoleBindings

CLUSTERROLEBINDING                           SUBJECT                         TYPE            SA-NAMESPACE
cluster-admin                                system:masters                  Group
tunnel-operator                           tunnel-operator              ServiceAccount  tunnel-system
system:controller:generic-garbage-collector  generic-garbage-collector       ServiceAccount  kube-system
system:controller:namespace-controller       namespace-controller            ServiceAccount  kube-system
system:controller:resourcequota-controller   resourcequota-controller        ServiceAccount  kube-system
system:kube-controller-manager               system:kube-controller-manager  User
```

If the `ClusterRoleBinding` does not exist, Tunnel currently cannot monitor any namespace outside of the `tunnel-system` namespace.

For instance, if you are using the [Helm Chart](./helm.md), you want to make sure to set the `targetNamespace` to the namespace that you want the Operator to monitor.

The operator also could not be configured to scan the workload you are expecting. Check to make sure `OPERATOR_TARGET_WORKLOADS` is set correctly in your configuration. This allows you to specify which workload types to be scanned. 

For example, by default in the [Helm Chart](./helm.md) values, the following Kubernetes workloads are configured to be scanned
`"pod,replicaset,replicationcontroller,statefulset,daemonset,cronjob,job"`.
