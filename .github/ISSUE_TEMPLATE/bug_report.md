---
name: Bug report
about: Create a report to help us improve the integration
title: " "
labels: Bug

---

## Configuration & Security Check
**Before submitting, please confirm you have checked the following:**

- [ ] **1. Web Management:** I confirm that the Web management interface is enabled on the router.
- [ ] **2. Port Forwarding:** I have configured Port Forwarding properly (e.g., Ext: `100` -> Int: `79`).
- [ ] **3. Firewall Rules:** I have configured Firewall rules to allow Home Assistant IP and deny others.

---

4. Mesh/AP Credentials Check
For **Mesh Extenders** and **Access Points**, the username and password are the **same as the Main Router**.
**Are you using the same Main Router's credentials for mesh extenders?**
- [ ] Yes
- [ ] No

---

## System Information
- **Router Model:** [e.g. Keenetic Hero DSL, Viva, Giga...]
- **Keenetic OS Version:** [e.g. 4.1.2]

---

## Describe the bug
Type your description here...

## To Reproduce
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

## Expected behavior
A clear and concise description of what you expected to happen.

## Debug Log
<details>
  <summary>Click to expand logs</summary>

  ```yaml
  logger:
    default: warning
    logs:
      custom_components.keenetic_router_pro: debug
