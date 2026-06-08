FROM node:20-alpine AS builder
WORKDIR /app

# Install librsvg for SVG → PNG icon generation
RUN apk add --no-cache librsvg

COPY package.json ./
RUN npm install
COPY . .

# Generate PNG icons from SVG for PWA manifest
RUN rsvg-convert -w 192 -h 192 public/favicon.svg -o public/icon-192.png
RUN rsvg-convert -w 512 -h 512 public/favicon.svg -o public/icon-512.png

RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
