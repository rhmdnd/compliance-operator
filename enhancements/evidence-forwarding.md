---
title: Evidence Forwarding
authors:
  - rhmdnd
  - JAORMX
reviewers:
  - TBD
approvers:
  - TBD
api-approvers: # In case of new or modified APIs or API extensions (CRDs, aggregated apiservers, webhooks, finalizers). If there is no API change, use "None"
  - TBD
creation-date: 2022-07-12
last-updated: 2022-07-12
tracking-link: # link to the tracking ticket (for example: Jira Feature or Epic ticket) that corresponds to this enhancement
  - TBD
---

To get started with this template:
1. **Pick a domain.** Find the appropriate domain to discuss your enhancement.
1. **Make a copy of this template.** Copy this template into the directory for
   the domain.
1. **Fill out the "overview" sections.** This includes the Summary and
   Motivation sections. These should be easy and explain why the community
   should desire this enhancement.
1. **Create a PR.** Assign it to folks with expertise in that domain to help
   sponsor the process.
1. **Merge at each milestone.** Merge when the design is able to transition to a
   new status (provisional, implementable, implemented, etc.). View anything
   marked as `provisional` as an idea worth exploring in the future, but not
   accepted as ready to execute. Anything marked as `implementable` should
   clearly communicate how an enhancement is coded up and delivered. If an
   enhancement describes a new deployment topology or platform, include a
   logical description for the deployment, and how it handles the unique aspects
   of the platform. Aim for single topic PRs to keep discussions focused. If you
   disagree with what is already in a document, open a new PR with suggested
   changes.
1. **Keep all required headers.** If a section does not apply to an
   enhancement, explain why but do not remove the section. This part
   of the process is enforced by the linter CI job.

See ../README.md for background behind these instructions.

Start by filling out the header with the metadata for this enhancement.

# Evidence Forwarding

## Summary

Compliance audits usually require evidence that proves an environment is
compliant. While the compliance operator provides check results as a Custom
Resource, users an generate complete reports in an [Asset Reporting Format
(ARF)](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/arf).
These reports can be large and verbose. A single report for a small cluster can
generate about 3 MB of data. This increase with each scan run, and with the
amount of infrastructure being scanned.

Historically, the Compliance Operator saves these reports to a physical volume.
This works around saving the entire report in Custom Resource Definitions,
which are bound to limitations of etcd.

Unfortunately, physical volumes have their own short-comings. Reports stored in
physical volumes still need to be fetched for evidence. Physical volumes can
also be deleted like any other cluster resource.

A improvement to the idea of putting evidence reports on disk would be to dump
them into an object or file store. This has an added benefit of allowing
administrators managing multiple clusters to put evidence in a single location.

## Motivation

The motivation of the enhancement is to store compliance evidence outside the
cluster and its storage pools.

### Goals

The goal is to provide a way for Kubernetes administrators to configure the
Compliance Operator to send compliance reports, specifically ARF reports, to an
external storage pool, like an object or file store.

### Non-Goals

It is not the goal of this enhancement to implement results forwarding, or
adjust the definition of evidence outside an ARF report.

## Proposal

Provide an additional configuration for scan settings that allows site
reliability engineers to forward evidence to a storage pool. Today, the
Compliance Operator provides a `default` `ScanSetting` that integrates with
persistent storage:

```yaml
---
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSetting
metadata:
  name: default
  namespace: openshift-compliance
rawResultStorage:
  pvAccessModes:
  - ReadWriteOnce
  rotation: 3
  size: 1Gi
roles:
- worker
- master
scanTolerations:
  default:
  - operator: Exists
  schedule: 0 1 * * *
```

A site reliability engineer could create another `ScanSetting` that bypasses
storing evidence on physical volumes with the following:

```yaml
---
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSetting
metadata:
  name: external-storage
  namespace: openshift-compliance
externalResultStorage:
  endpoint: https://object-storage.example.com/
  tls:
roles:
- worker
- master
scanTolerations:
  default:
  - operator: Exists
  schedule: 0 1 * * *
```

A site reliability engineer could configure both storage mechanisms for redundancy:

```yaml
---
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSetting
metadata:
  name: external-storage-and-cluster-storage
  namespace: openshift-compliance
rawResultStorage:
  pvAccessModes:
  - ReadWriteOnce
  rotation: 3
  size: 1Gi
externalResultStorage:
  endpoint: https://object-storage.example.com/
  tls:
roles:
- worker
- master
scanTolerations:
  default:
  - operator: Exists
  schedule: 0 1 * * *
```

### User Stories

1. As a site reliability engineer, I want to configure the Compliance Operator
   to send all ARF reports to a dedicated object store.
2. As a site reliability engineer, I want to opt out of storing any ARF reports
   on physical volumes.
3. As a site reliability engineer, I expect verbose alerts when the Compliance
   Operator cannot send ARF reports to a configured external storage pool.
4. As a site reliability engineer, I expect the Compliance Operator to fail if
   the configured endpoint is unreachable.
5. As a site reliability engineer, I expect to forward evidence to
   public object-storage endpoints, like AWS S3.
5. As a site reliability engineer, I expect to forward evidence to
   private object-storage endpoints in cluster, Ceph or OpenShift Data Foundation.

### API Extensions

This proposal would extend the `ScanSetting` custom resource definition (CRD)
to include an additional attribute called `externalResultStorage`.

## `externalResultStorage`

This attribute is an *optional* argument to `ScanSetting` CRDs. Existing
instances of `ScanSetting` custom resources will be treated as if they're not
configured to use external storage, making the feature backwards compatible.

###  `endpoint`

The `endpoint` is a required argument for `externalResultStorage`. The
Compliance Operator will validate the `endpoint` at runtime (e.g., when a
`ScanSetting` is created or used) to ensure connectivity. This doesn't
necessarily mean the endpoint will always be available, but it is important to
fail early if the URL is malformed.

###  `tls`


### Implementation Details/Notes/Constraints [optional]

There is a chance that we will have requests for different forwarding
implementations. We should abstract the forwarding interface from the actual
forwarding implementation, which can be loaded when the operator starts.

### Risks and Mitigations

One potential risk users face when using this feature is the availability of
the storage endpoint. What should the Compliance Operator do if it needs to
forward evidence, but the endpoint isn't available?

The operator should absolutely emit an alert.

The configuration described above can include storing the evidence on a
physical volume as well as externally. This helps, but we should document that
the operator does not attempt to persist evidence if it's only configured for
forward to an external store.

## Design Details

### Open Questions [optional]

 > 1. What external storage implementations do we want to target initially
 >    (e.g., AWS S3, Ceph Object Gateway)?

AWS S3 is widely used, so it feels like a natural choice. But, an in-cluster
option for object-storage is appealing for users who don't want to store
evidence of physical volumes.

### Test Plan

Testing this feature can leverage existing end-to-end testing built into the
ComplianceAsCode/compliance-operator CI using OpenShift.

To test, we could build a job that uses existing AWS resources to configure
evidence forwarding (assuming we target S3). From there, we can perform scans,
forward the evidence, and use a storage client to assert the results made it
through to the external system.

Since this feature is limited to forwarding results, modifying evidence is out
of scope for testing.

### Upgrade / Downgrade Strategy

The functionality and additional `ScanSetting` configuration described here is
optional and backwards compatible with existing `ScanSetting` objects. Existing
`ScanSetting` custom resources will continue to work on upgrade.

The Compliance Operator does not support a downgrade path, short of reinstalling.

### Version Skew Strategy

The `ScanSetting` CRD version will be incremented to advertise the changes.

### Operational Aspects of API Extensions

Operationally, SREs can expect the operator to valid the endpoint at runtime
when validating or using a `ScanSetting` configured to persist evidence in
external storage. This will increase the time it takes to post-process evidence.

Additionally, external storage endpoints that are misconfigured, will result in
failed scans. SREs are expected to resolve these issues before the
`ScanSetting` can be used.

#### Failure Modes

- If the `externalResultStorage.endpoint` is unreachable after the scan is performed, the operator will issue an alert
  - It will continue to store the results in a physical volume if configured to do so
- If the `externalResultStorage.endpoint` is unreachable when the `ScanSetting` is created, creation will fail

#### Support Procedures

In the event the `endpoint` is misconfigured, an SRE is expected to update it
accordingly. SRE will be able to detect this issue by monitoring alerts sent to
the `openshift-compliance` namespace.

SREs can remediate the issue by checking the `endpoint` and updating it by
editing the `ScanSetting` resource.

## Implementation History

This was initially discussed in another
[enhancement](https://github.com/ComplianceAsCode/compliance-operator/pull/2),
but it was decided that we should keep evidence and result forwarding separate.
The primary reason for this decision is that evidence can be unbounded, whereas
results are specific.

## Drawbacks

This implementation will complicate existing results and evidence processing.
We also need to handle failure scenarios appropriately, which are dependent on
an external system.

## Alternatives

An alternative would be to find a way to shuffle evidence from physical volumes
to external storage, bypassing the need for native evidence forwarding the
Compliance Operator.

This doesn't address existing
[concerns](https://github.com/ComplianceAsCode/compliance-operator/pull/2#issuecomment-1158426389)
users have about putting evidence in physical volumes.


## Infrastructure Needed [optional]

The only additional resource needed at this time would potentially be an external storage implementation (OpenShift Data Foundation, AWS S3, etc).
