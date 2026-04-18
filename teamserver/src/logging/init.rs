#[cfg(feature = "otel")]
use red_cell_common::config::ObservabilityConfig;
use red_cell_common::config::Profile;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, registry};

use super::config::{
    LoggingGuard, LoggingInitError, ResolvedLoggingConfig, resolve_logging_config,
};
use super::rotation::file_writer;

// ---------------------------------------------------------------------------
// Trace-context injection layer (otel feature only)
// ---------------------------------------------------------------------------

/// A [`tracing_subscriber::Layer`] that stores OpenTelemetry `trace_id` and
/// `span_id` in span extensions so that log formatters can include them.
///
/// Without this layer the `fmt` layer has no knowledge of OTel context and
/// JSON log lines lack correlation IDs.  When enabled (behind the `otel`
/// feature flag), this layer reads the OTel context from the parent span
/// (populated by `tracing-opentelemetry`) and stores the hex-encoded IDs as
/// [`TraceContext`] in span extensions.
#[cfg(feature = "otel")]
struct TraceContextLayer;

#[cfg(feature = "otel")]
impl<S> tracing_subscriber::Layer<S> for TraceContextLayer
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_new_span(
        &self,
        _attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        use opentelemetry::trace::TraceContextExt as _;

        let Some(span) = ctx.span(id) else {
            return;
        };
        let extensions = span.extensions();
        let otel_data = extensions.get::<tracing_opentelemetry::OtelData>();
        if let Some(data) = otel_data {
            let trace_id = data.parent_cx.span().span_context().trace_id();
            let span_id = data.parent_cx.span().span_context().span_id();

            if trace_id != opentelemetry::trace::TraceId::INVALID {
                drop(extensions);
                let mut extensions_mut = span.extensions_mut();
                extensions_mut.insert(TraceContext {
                    trace_id: format!("{trace_id}"),
                    span_id: format!("{span_id}"),
                });
            }
        }
    }
}

/// Stored in span extensions by [`TraceContextLayer`] so that log formatters
/// can include trace correlation IDs.
#[cfg(feature = "otel")]
#[derive(Debug, Clone)]
pub(crate) struct TraceContext {
    pub(crate) trace_id: String,
    pub(crate) span_id: String,
}

/// A [`FormatEvent`] wrapper that prepends `trace_id` and `span_id` fields
/// to JSON log output when available.
///
/// Walks up the span stack looking for [`TraceContext`] in extensions.  When
/// found, it writes `{"trace_id":"…","span_id":"…",…}` instead of `{…}`.
/// Falls back to the inner formatter when no trace context is present.
#[cfg(feature = "otel")]
struct OtelJsonFormat;

#[cfg(feature = "otel")]
impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for OtelJsonFormat
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        // Collect trace context from the closest span that has it.
        let mut trace_id: Option<String> = None;
        let mut span_id: Option<String> = None;

        if let Some(scope) = ctx.event_scope() {
            for span_ref in scope {
                let exts = span_ref.extensions();
                if let Some(tc) = exts.get::<TraceContext>() {
                    trace_id = Some(tc.trace_id.clone());
                    span_id = Some(tc.span_id.clone());
                    break;
                }
            }
        }

        // Build a JSON object with standard fields.
        let meta = event.metadata();
        let now = time::OffsetDateTime::now_utc();

        // Format timestamp as RFC 3339.
        let ts = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| now.to_string());

        write!(writer, "{{\"timestamp\":\"{ts}\"")?;
        write!(writer, ",\"level\":\"{}\"", meta.level())?;

        if let Some(tid) = trace_id {
            write!(writer, ",\"trace_id\":\"{tid}\"")?;
        }
        if let Some(sid) = span_id {
            write!(writer, ",\"span_id\":\"{sid}\"")?;
        }

        // Collect span names for context.
        if let Some(scope) = ctx.event_scope() {
            write!(writer, ",\"spans\":[")?;
            let mut first = true;
            for span_ref in scope {
                if !first {
                    write!(writer, ",")?;
                }
                let json_name = span_ref.name().replace('"', "\\\"");
                write!(writer, "\"{}\"", json_name)?;
                first = false;
            }
            write!(writer, "]")?;
        }

        // Collect event fields.
        write!(writer, ",\"fields\":{{")?;
        let mut field_visitor = JsonFieldVisitor::new();
        event.record(&mut field_visitor);
        write!(writer, "{}", field_visitor.output)?;
        write!(writer, "}}")?;

        writeln!(writer, "}}")?;
        Ok(())
    }
}

/// Simple visitor that serialises fields as JSON key-value pairs.
#[cfg(feature = "otel")]
struct JsonFieldVisitor {
    output: String,
    first: bool,
}

#[cfg(feature = "otel")]
impl JsonFieldVisitor {
    fn new() -> Self {
        Self { output: String::new(), first: true }
    }

    fn comma(&mut self) {
        if !self.first {
            self.output.push(',');
        }
        self.first = false;
    }
}

#[cfg(feature = "otel")]
impl tracing::field::Visit for JsonFieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        self.comma();
        let _ = write!(self.output, "\"{}\":\"{:?}\"", field.name(), value);
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.comma();
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        self.output.push_str(&format!("\"{}\":\"{}\"", field.name(), escaped));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.comma();
        self.output.push_str(&format!("\"{}\":{}", field.name(), value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.comma();
        self.output.push_str(&format!("\"{}\":{}", field.name(), value));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.comma();
        self.output.push_str(&format!("\"{}\":{}", field.name(), value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.comma();
        self.output.push_str(&format!("\"{}\":{}", field.name(), value));
    }
}

/// Build an OpenTelemetry tracer provider when the `otel` feature is active.
///
/// Returns `None` when no OTLP endpoint is configured.  The caller creates
/// the tracing layer from the returned provider so that the subscriber type
/// parameter `S` is inferred at the call site.
#[cfg(feature = "otel")]
pub(super) fn build_otel_provider(
    config: Option<&ObservabilityConfig>,
) -> Result<Option<opentelemetry_sdk::trace::SdkTracerProvider>, LoggingInitError> {
    let Some(cfg) = config else {
        return Ok(None);
    };
    let Some(ref endpoint) = cfg.otlp_endpoint else {
        return Ok(None);
    };

    use opentelemetry_otlp::WithExportConfig as _;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::SdkTracerProvider;

    let service_name = cfg.service_name.as_deref().unwrap_or("red-cell-teamserver");

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e: opentelemetry::trace::TraceError| LoggingInitError::OpenTelemetry {
            message: e.to_string(),
        })?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(Resource::builder().with_service_name(service_name.to_owned()).build())
        .build();

    Ok(Some(provider))
}

/// Create a `tracing_opentelemetry` layer from an optional provider.
///
/// Returns `None` when no provider is supplied, keeping the subscriber
/// unmodified (the `Option<Layer>` no-ops in `tracing-subscriber`).
#[cfg(feature = "otel")]
pub(super) fn otel_layer_from_provider(
    provider: &Option<opentelemetry_sdk::trace::SdkTracerProvider>,
) -> Option<
    tracing_opentelemetry::OpenTelemetryLayer<
        tracing_subscriber::Registry,
        opentelemetry_sdk::trace::Tracer,
    >,
> {
    use opentelemetry::trace::TracerProvider as _;
    provider.as_ref().map(|p| {
        let tracer = p.tracer("red-cell-teamserver");
        tracing_opentelemetry::layer().with_tracer(tracer)
    })
}

pub fn init_tracing(
    profile: Option<&Profile>,
    debug_logging: bool,
) -> Result<LoggingGuard, LoggingInitError> {
    let ResolvedLoggingConfig { filter_directive, format, file } =
        resolve_logging_config(profile, debug_logging);
    let filter = EnvFilter::try_new(filter_directive.clone()).map_err(|error| {
        LoggingInitError::InvalidFilter {
            directive: filter_directive.clone(),
            message: error.to_string(),
        }
    })?;

    // Resolve optional OTel provider (only compiled in when the `otel` feature is active).
    #[cfg(feature = "otel")]
    let otel_config = profile.and_then(|p| p.teamserver.observability.as_ref());
    #[cfg(feature = "otel")]
    let otel_provider = build_otel_provider(otel_config)?;
    #[cfg(feature = "otel")]
    let otel_layer = otel_layer_from_provider(&otel_provider);

    // Build the base subscriber with the OTel layer positioned directly on the
    // registry so that `OpenTelemetryLayer<Registry, T>` matches its `Layer<Registry>`
    // impl.  The OTel layer is `Option<_>`, so it no-ops when absent.
    //
    // `TraceContextLayer` sits above the OTel layer so it can read `OtelData`
    // from span extensions and store `TraceContext` for the fmt layer to pick up.
    let base = registry();
    #[cfg(feature = "otel")]
    let base = base.with(otel_layer);
    #[cfg(feature = "otel")]
    let trace_ctx_layer: Option<TraceContextLayer> =
        if otel_provider.is_some() { Some(TraceContextLayer) } else { None };
    #[cfg(feature = "otel")]
    let base = base.with(trace_ctx_layer);

    let init_err = |error: tracing_subscriber::util::TryInitError| {
        LoggingInitError::InitializeSubscriber { message: error.to_string() }
    };

    match (format, file) {
        (red_cell_common::config::LogFormat::Pretty, None) => {
            base.with(filter)
                .with(
                    fmt::layer().pretty().with_target(false).with_file(true).with_line_number(true),
                )
                .try_init()
                .map_err(init_err)?;

            Ok(LoggingGuard {
                _file_guard: None,
                #[cfg(feature = "otel")]
                _otel_provider: otel_provider,
            })
        }
        (red_cell_common::config::LogFormat::Json, None) => {
            // When the `otel` feature is active, use `OtelJsonFormat` to inject
            // `trace_id` and `span_id` into JSON log lines.  When the feature is
            // off, use the standard `tracing-subscriber` JSON format.
            #[cfg(feature = "otel")]
            {
                base.with(filter)
                    .with(fmt::layer().event_format(OtelJsonFormat))
                    .try_init()
                    .map_err(init_err)?;
            }
            #[cfg(not(feature = "otel"))]
            {
                base.with(filter)
                    .with(fmt::layer().json().with_target(false))
                    .try_init()
                    .map_err(init_err)?;
            }

            Ok(LoggingGuard {
                _file_guard: None,
                #[cfg(feature = "otel")]
                _otel_provider: otel_provider,
            })
        }
        (red_cell_common::config::LogFormat::Pretty, Some(file)) => {
            let (writer, guard) = file_writer(&file)?;
            base.with(filter)
                .with(
                    fmt::layer().pretty().with_target(false).with_file(true).with_line_number(true),
                )
                .with(fmt::layer().pretty().with_ansi(false).with_target(false).with_writer(writer))
                .try_init()
                .map_err(init_err)?;

            Ok(LoggingGuard {
                _file_guard: Some(guard),
                #[cfg(feature = "otel")]
                _otel_provider: otel_provider,
            })
        }
        (red_cell_common::config::LogFormat::Json, Some(file)) => {
            let (writer, guard) = file_writer(&file)?;
            #[cfg(feature = "otel")]
            {
                base.with(filter)
                    .with(fmt::layer().event_format(OtelJsonFormat))
                    .with(fmt::layer().event_format(OtelJsonFormat).with_writer(writer))
                    .try_init()
                    .map_err(init_err)?;
            }
            #[cfg(not(feature = "otel"))]
            {
                base.with(filter)
                    .with(fmt::layer().json().with_target(false))
                    .with(fmt::layer().json().with_target(false).with_writer(writer))
                    .try_init()
                    .map_err(init_err)?;
            }

            Ok(LoggingGuard {
                _file_guard: Some(guard),
                #[cfg(feature = "otel")]
                _otel_provider: otel_provider,
            })
        }
    }
}
