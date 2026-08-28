FROM node@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS dependencies

WORKDIR /opt/guard
COPY packages/guard/package.json packages/guard/package-lock.json ./
RUN npm ci --ignore-scripts

FROM node@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS agent
WORKDIR /opt/guard
COPY --from=dependencies /opt/guard/node_modules ./node_modules
COPY packages/guard/test/fixtures/container-enforcement/vercel-provider-probe.mjs ./vercel-provider-probe.mjs
USER 65532:65532
CMD ["node", "-e", "setInterval(() => {}, 60_000)"]

FROM node@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS gateway
WORKDIR /opt/guard
COPY --from=dependencies /opt/guard/node_modules ./node_modules
COPY packages/guard/dist ./dist
COPY packages/guard/test/fixtures/container-enforcement/guard-gateway.mjs ./guard-gateway.mjs
USER 65532:65532
CMD ["node", "/opt/guard/guard-gateway.mjs"]

FROM node@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS identity-broker
WORKDIR /opt/guard
COPY packages/guard/dist ./dist
COPY packages/guard/test/fixtures/kubernetes-enforcement/identity-broker.mjs ./identity-broker.mjs
USER 65532:65532
CMD ["node", "/opt/guard/identity-broker.mjs"]
