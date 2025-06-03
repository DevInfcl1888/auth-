# Use the latest Node.js LTS version as the base image
FROM node:lts-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies (use --legacy-peer-deps if necessary for compatibility)
RUN npm install --no-audit --no-fund

# Install the latest versions of nodemon and ts-node globally
RUN npm install -g nodemon@latest ts-node@latest

# Copy the rest of the application code
COPY . .

# Expose the application's port
EXPOSE 8080

# Command to run the development server with auto-reloading
CMD ["npx", "nodemon", "--watch", "src", "--exec", "ts-node", "src/index.ts"]
