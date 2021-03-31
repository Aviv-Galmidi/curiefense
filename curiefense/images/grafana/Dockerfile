FROM grafana/grafana:latest-ubuntu

COPY --chown=grafana:grafana provisioning/dashboards/* /etc/grafana/provisioning/dashboards/

COPY --chown=grafana:grafana provisioning/datasources/* /etc/grafana/provisioning/datasources/
