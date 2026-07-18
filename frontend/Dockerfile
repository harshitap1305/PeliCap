FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . .

# Expose port 3000
EXPOSE 3000

# Start Vite dev server exposing to all network interfaces
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
