# Vigía

> Agente OSINT de superficie de ataque externa (EASM), potenciado por un LLM local.

*[English version](README.md)*

**Estado: Fase 6 de 9 completada** (Base, Tools pasivas, Agente, Riesgo e Informe,
GUI núcleo, GUI avanzada). Usable de punta a punta para escaneos pasivos, tanto por
CLI como desde el panel web bilingüe (ES/EN) — incluye el visor de informes, el
grafo de activos, el registro de auditoría y una página de Ajustes para modelo,
presupuestos y claves de API. Consulta [CLAUDE.md](CLAUDE.md) para el estado exacto
y los comandos disponibles.

## ¿Qué es Vigía?

Dado un dominio propio o para el que tienes autorización explícita, Vigía usa un LLM
local (vía [Ollama](https://ollama.com)) como agente para enumerar su superficie de
ataque externa — subdominios, servicios expuestos, malas configuraciones de DNS/email,
registros DNS huérfanos, secretos filtrados y más —, verifica cada hallazgo contra
evidencia en crudo almacenada, lo prioriza con datos de CISA KEV y FIRST EPSS, y lo
presenta todo en un panel web con un grafo de activos y un informe exportable.

Es un proyecto de portfolio para trabajo de SOC/Blue Team: la calidad del código, los
tests, los guardrails y la documentación importan tanto como las funcionalidades.

Principio de diseño: el LLM **decide y redacta** (qué investigar a continuación, cómo
escribir el informe); el código determinista **ejecuta, normaliza, puntúa y valida**.
El LLM nunca ejecuta comandos arbitrarios ni construye argumentos de herramientas fuera
de un schema fijo.

## Estado

Este repositorio está en desarrollo activo y por fases. Nada aquí debe considerarse
listo para producción. Consulta [CLAUDE.md](CLAUDE.md) para saber exactamente qué
funciona hoy.

## Uso ético

Vigía solo debe ejecutarse contra dominios propios o para los que tengas autorización
explícita por escrito. Consulta [docs/ethics.md](docs/ethics.md).

## Documentación

- [CLAUDE.md](CLAUDE.md) — comandos, convenciones, estado actual
- [docs/architecture.md](docs/architecture.md)
- [docs/decisions.md](docs/decisions.md) — registro de ADRs
- [docs/ethics.md](docs/ethics.md)

## Licencia

[MIT](LICENSE)
