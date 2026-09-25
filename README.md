# CA-DOF-TDE
CA-DOF is working on automating and validating TDE key rotation, including Azure Key Vault and SQL Managed Instance integration. The implementation direction has moved toward self-hosted VM-based PowerShell automation with private connectivity. 

# CA-DOF TDE Key Rotation Automation

## Overview

This repository supports the California Department of Finance (CA-DOF) Transparent Data Encryption (TDE) key rotation automation workstream. The objective is to provide a secure, repeatable, and supportable process for validating and synchronizing customer-managed TDE keys across Azure Key Vault, Azure SQL Managed Instance, and applicable SQL Server environments hosted on Azure virtual machines.

The implementation is currently in the proof-of-concept and validation phase. The working direction has evolved from an Azure Functions-based design to a self-hosted virtual machine running PowerShell automation, while retaining private endpoint connectivity and controlled access to Azure resources.

## Current Status

- A self-hosted VM-based implementation has been selected for the current proof of concept.
- Private connectivity remains part of the target approach.
- A VM has been provisioned for validating PowerShell-based automation against SQL Managed Instance and related Azure resources.
- The PowerShell workflow includes connectivity, configuration, key-version, and TDE validation checks.
- The implementation team is preparing the prerequisites and repeatable steps required for CA-DOF to reproduce the solution.
- End-to-end operational readiness, production controls, and support ownership still require formal validation and approval.

## Solution Objectives

The automation is intended to:

1. Connect securely to the approved Azure tenant and subscription.
2. Validate access to the designated Azure Key Vault.
3. Retrieve the active Key Vault key and its current version.
4. Inspect the TDE protector configured on Azure SQL Managed Instance.
5. Determine whether automatic key rotation is enabled.
6. Compare the Key Vault key version with the key registered on SQL Managed Instance.
7. Query SQL-side encryption metadata when database connectivity is available.
8. Validate encryptor thumbprint consistency where supported by the available metadata.
9. Report the previous and current key versions when they can be identified.
10. Produce clear console output, validation results, warnings, and recommended follow-up actions.

## High-Level Architecture

```text
Approved Administration Boundary
            |
            v
Self-Hosted Azure VM
  - PowerShell automation
  - Az PowerShell modules
  - SQL client connectivity
  - Managed identity or approved identity
            |
            +------------------------------+
            |                              |
            v                              v
Azure Key Vault                    Azure SQL Managed Instance
  - Customer-managed TDE key         - TDE protector configuration
  - Key versions                     - Auto-rotation status
  - Rotation policy                  - Registered Key Vault keys
  - Private endpoint                 - SQL encryption metadata
            |                              |
            +---------- Private Network --+
```

## Preferred Security Model

The target implementation should follow CA-DOF-approved identity, networking, and privileged-access standards.

Recommended controls include:

- Use managed identity where the automation design and operating model support it.
- If an interactive or service identity is required, apply least-privilege Azure RBAC and maintain an approved credential lifecycle.
- Keep Key Vault and SQL Managed Instance access on private network paths.
- Restrict VM access through approved administrative controls.
- Avoid storing passwords, access tokens, client secrets, or SQL credentials in source files.
- Use PowerShell secure credential objects or an approved secrets-management mechanism.
- Enable diagnostic logging for Key Vault and relevant Azure resources.
- Capture automation output in an approved operational logging location.
- Separate development, test, and production configuration and authorization boundaries.

## Prerequisites

### Azure Resources

- An approved Azure subscription and resource group
- Azure Key Vault containing the customer-managed TDE key
- Azure SQL Managed Instance configured for customer-managed TDE
- A self-hosted Azure VM with required network connectivity
- Private DNS
