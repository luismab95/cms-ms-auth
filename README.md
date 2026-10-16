# CMS-MS-AUTH

<p align="center">
  <a href="https://nestjs.com/" target="_blank">
    <img src="https://nestjs.com/img/logo-small.svg" width="120" alt="NestJS Logo" />
  </a>
</p>

<p align="center">
  Microservice for authentication and authorization in the CMS project.
</p>

<p align="center">
  <a href="https://github.com/luismab95/cms-ms-auth">
    <img src="https://img.shields.io/badge/NestJS-12-E0234E.svg" alt="NestJS 12" />
  </a>
  <a href="https://pnpm.io/">
    <img src="https://img.shields.io/badge/package%20manager-pnpm-F69220.svg" alt="pnpm" />
  </a>
  <a href="https://github.com/luismab95/cms-ms-auth/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" />
  </a>
</p>

## Description

CMS-MS-AUTH is an authentication and authorization microservice for the CMS project, built with [NestJS](https://nestjs.com/) and TypeScript.

It provides the foundation for managing authentication and authorization within the CMS ecosystem.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Running the App](#running-the-app)
- [Testing](#testing)
- [Building](#building)
- [Deployment](#deployment)
- [Resources](#resources)
- [License](#license)

## Requirements

Make sure the following tools are installed:

- [Node.js](https://nodejs.org/)
- [pnpm](https://pnpm.io/installation)
- Git

Use a Node.js version compatible with your installed NestJS version and project dependencies.

Verify your installations:

```bash
node -v
pnpm -v
```

## Installation

Clone the repository:

```bash
git clone https://github.com/luismab95/cms-ms-auth.git
```

Navigate to the project directory:

```bash
cd cms-ms-auth
```

Install dependencies:

```bash
pnpm install
```

## Environment Variables

Configure the environment variables required by the application before running it.

Create a `.env` file in the project root if your configuration uses environment files.

Example:

```env
NODE_ENV=development
PORT=3000
```

Adjust these variables according to the application's configuration and the services it depends on.

**Note:** The variables shown above are examples. Check the application configuration to identify the actual required variables.

## Running the App

### Development

```bash
pnpm start
```

### Watch Mode

Automatically restart the application when files change:

```bash
pnpm start:dev
```

### Debug Mode

```bash
pnpm start:debug
```

### Production

```bash
pnpm start:prod
```

Build the application before running it in production:

```bash
pnpm build
pnpm start:prod
```

## Testing

### Unit Tests

```bash
pnpm test
```

### Watch Mode

```bash
pnpm test:watch
```

### End-to-End Tests

```bash
pnpm test:e2e
```

### Test Coverage

```bash
pnpm test:cov
```

## Building

Compile the application:

```bash
pnpm build
```

The compiled output is generated in the `dist` directory by the standard NestJS build configuration.

## Deployment

Before deploying to production:

- Configure production environment variables.
- Build the application using `pnpm build`.
- Ensure dependencies are installed consistently using the committed `pnpm-lock.yaml`.
- Configure the required database connections and external services.
- Verify that authentication and authorization flows work correctly.
- Configure logging, monitoring, and error handling.

For additional information, see the [NestJS deployment documentation](https://docs.nestjs.com/deployment).

## Resources

- [NestJS Documentation](https://docs.nestjs.com)
- [NestJS Official Website](https://nestjs.com)
- [pnpm Documentation](https://pnpm.io)
- [Node.js Documentation](https://nodejs.org/docs)
- [CMS-MS-AUTH Repository](https://github.com/luismab95/cms-ms-auth)

## License

This project is licensed under the MIT License.

See the [LICENSE](LICENSE) file for details.