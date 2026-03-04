# Vulnerability Priority by System Type

## Web API / REST Backend
**Priority**: BOLA/IDOR, Broken Function-Level Auth, Injection, SSRF, Mass Assignment
**Focus**: Trace every endpoint for authz checks, test all parameters for injection, check all outbound HTTP calls

## Management System / Admin Panel
**Priority**: Broken Access Control, IDOR, Role Escalation, Multi-tenant Isolation, CSRF
**Focus**: Test every admin function for authz bypass, enumerate all object references, test role boundaries

## Authentication / Identity Service
**Priority**: Auth Bypass, Token Forgery, Session Attacks, Redirect Bypass, Credential Handling
**Focus**: Trace all auth flows, test token generation, analyze session lifecycle, check redirect validation

## CMS / Content Platform
**Priority**: XSS (stored), Template Injection, File Upload, Privilege Escalation, CSRF
**Focus**: Test all content rendering, check upload handlers, test editor permissions

## File Processing / Document Service
**Priority**: Path Traversal, XXE, Deserialization, SSRF, RCE via Parser
**Focus**: Test all file format parsers, check path construction, analyze XML/YAML handling

## Native Application (C/C++/Rust)
**Priority**: Buffer Overflow, Use-After-Free, Format String, Integer Overflow, Memory Corruption
**Focus**: Audit all input parsing, check buffer operations, analyze memory management

## Microservice Architecture
**Priority**: SSRF, Service-to-Service Auth, Secret Exposure, API Gateway Bypass, Deserialization
**Focus**: Map service mesh, test inter-service auth, check secret management
