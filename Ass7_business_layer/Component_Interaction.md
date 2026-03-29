# Core Functional Modules and Interaction with Presentation Layer

## Core Functional Modules (Business Logic Layer)

The SOAR platform consists of the following core business logic modules:

### 1. Alert Processing Module
- Receives alerts from various sources
- Stores alerts in the database
- Classifies alerts based on severity and type

### 2. Threat Intelligence Module
- Checks if IPs or domains are malicious
- Matches alerts with threat intelligence database
- Assigns threat level

### 3. Playbook Engine
- Executes predefined response rules
- Automates actions such as blocking IPs or generating alerts

### 4. Notification Module
- Sends alerts to users or administrators
- Stores notification logs

### 5. User Management Module
- Handles authentication and authorization
- Manages user roles and access control

### 6. Logging and Audit Module
- Records system activities
- Maintains audit logs for tracking actions

---

## Interaction with Presentation Layer (User Interface)

The frontend (React-based UI) interacts with backend modules through REST APIs.

### 1. Login Page Interaction
- UI sends login credentials to backend
- Backend validates user and returns authentication token

### 2. Alerts Dashboard Interaction
- UI requests alerts using API (GET /alerts)
- Backend retrieves alerts from database and returns data
- UI displays alerts in table format

### 3. Threat Intelligence Interaction
- UI sends IP or domain to backend
- Backend checks threat intelligence database
- Returns threat status

### 4. Playbook Manager Interaction
- UI triggers playbook execution
- Backend processes playbook rules and executes actions

### 5. Notifications Interaction
- UI fetches notifications
- Backend returns stored notification data

---

## In Short

The business logic layer is composed of multiple modules such as alert processing, threat intelligence, playbook execution, notification handling, user management, and audit logging. These modules interact with the presentation layer through API calls, enabling the user interface to display data and trigger actions dynamically.
