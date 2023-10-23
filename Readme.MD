# Role-Based Authentication Server

This is a role-based authentication server built using Go and Fiber. It provides user registration, authentication, role
management, and role-based access control. Users can sign up, log in, and be assigned different roles with specific
permissions.

### Table of Contents

[Getting Started](#getting-started)\
[Prerequisites](#prerequisites)\
[Installation](#installation)\
[Usage](#usage)\
[API Endpoints](#api-endpoints)\
[Features](#features)\
[Contributing](#contributing)\
[License](#license)

#### Getting Started

These instructions will help you set up and run the authentication server on your local machine for development and
testing purposes.\
Visit the blog for step-by-step tutorial \
https://medium.com/@tanveeshs/creating-an-role-based-authentication-server-using-golang-and-fiber-3367341cf7c5
#### Prerequisites

You will need the following software and services installed:

- Go
- MongoDB
- Redis

#### Installation

1. Clone the repository:

```shell
git clone https://github.com/Tanveeshs/Go-Auth-Server
```

2. Navigate to the project directory:

```shell
cd auth-server
```

shell

3. Install Go dependencies:

```shell
go mod tidy
```

4. Update the configuration:\
   Make sure your MongoDB and Redis server configurations are correctly set in the main.go file.

5. Run the application:

```shell
go run main.go
```

The server should now be running at http://localhost:3000.

#### Usage

This section provides an overview of the server's features and how to use them.

#### API Endpoints

The following API endpoints are available:

- POST /signup: Register a new user.
- POST /login: Authenticate and receive a JWT token.
- POST /addPermission: Add a new permission to a user.
- POST /adminTestRoute: An example route that requires admin access.

#### Features

The authentication server uses industry-standard security measures, including:

- Password hashing for user credentials.
- JWT-based authentication and authorization.
- Role-based access control.
- Protection against common web vulnerabilities like SQL injection and XSS.
- Make sure to set strong and unique values for the SecretKey and any other sensitive configuration variables.

#### Contributing

I welcome contributions to this project. To contribute:

- Fork the repository.
- Create a feature branch.
- Make your changes and commit them.
- Push to your fork and submit a pull request.
- Please ensure your code follows the project's coding standards and includes appropriate tests and documentation.

#### License

This project is licensed under the MIT License - see the LICENSE file for details.