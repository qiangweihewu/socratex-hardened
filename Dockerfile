FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --chown=node:node main.mjs index.mjs ./
COPY --chown=node:node lib ./lib
USER node
ENV HOME=/home/node
VOLUME ["/home/node"]
EXPOSE 8080
ENTRYPOINT ["node", "main.mjs"]
CMD ["--port=8080"]
