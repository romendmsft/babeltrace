/*
 * BabelTrace - Common Trace Format (CTF)
 *
 * CTF Text Format registration.
 *
 * Copyright 2010-2011 EfficiOS Inc. and Linux Foundation
 *
 * Author: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <babeltrace/format.h>
#include <babeltrace/ctf-text/types.h>
#include <babeltrace/ctf/metadata.h>
#include <babeltrace/babeltrace-internal.h>
#include <babeltrace/ctf/events-internal.h>
#include <babeltrace/trace-debug-info.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <glib.h>
#include <unistd.h>
#include <stdlib.h>

#define NSEC_PER_SEC 1000000000ULL

int opt_all_field_names,
	opt_scope_field_names,
	opt_header_field_names,
	opt_context_field_names,
	opt_payload_field_names,
	opt_all_fields,
	opt_trace_field,
	opt_trace_domain_field,
	opt_trace_procname_field,
	opt_trace_vpid_field,
	opt_trace_hostname_field,
	opt_trace_default_fields = 1,
	opt_loglevel_field,
	opt_emf_field,
	opt_callsite_field,
	opt_delta_field = 1,
	opt_debug_info_full_path;

enum field_item {
	ITEM_SCOPE,
	ITEM_HEADER,
	ITEM_CONTEXT,
	ITEM_PAYLOAD,
};

enum bt_loglevel {
        BT_LOGLEVEL_EMERG                  = 0,
        BT_LOGLEVEL_ALERT                  = 1,
        BT_LOGLEVEL_CRIT                   = 2,
        BT_LOGLEVEL_ERR                    = 3,
        BT_LOGLEVEL_WARNING                = 4,
        BT_LOGLEVEL_NOTICE                 = 5,
        BT_LOGLEVEL_INFO                   = 6,
        BT_LOGLEVEL_DEBUG_SYSTEM           = 7,
        BT_LOGLEVEL_DEBUG_PROGRAM          = 8,
        BT_LOGLEVEL_DEBUG_PROCESS          = 9,
        BT_LOGLEVEL_DEBUG_MODULE           = 10,
        BT_LOGLEVEL_DEBUG_UNIT             = 11,
        BT_LOGLEVEL_DEBUG_FUNCTION         = 12,
        BT_LOGLEVEL_DEBUG_LINE             = 13,
        BT_LOGLEVEL_DEBUG                  = 14,
};

static
struct bt_trace_descriptor *ctf_text_open_trace(const char *path,
		//
		const char *table_config_path,
		const char *table_path,
		//
		int flags,
		void (*packet_seek)(struct bt_stream_pos *pos, size_t index,
			int whence), FILE *metadata_fp);
static
int ctf_text_close_trace(struct bt_trace_descriptor *descriptor);

static
rw_dispatch write_dispatch_table[] = {
	[ CTF_TYPE_INTEGER ] = ctf_text_integer_write,
	[ CTF_TYPE_FLOAT ] = ctf_text_float_write,
	[ CTF_TYPE_ENUM ] = ctf_text_enum_write,
	[ CTF_TYPE_STRING ] = ctf_text_string_write,
	[ CTF_TYPE_STRUCT ] = ctf_text_struct_write,
	[ CTF_TYPE_VARIANT ] = ctf_text_variant_write,
	[ CTF_TYPE_ARRAY ] = ctf_text_array_write,
	[ CTF_TYPE_SEQUENCE ] = ctf_text_sequence_write,
};

static
struct bt_format ctf_text_format = {
	.open_trace = ctf_text_open_trace,
	.close_trace = ctf_text_close_trace,
};

static GQuark Q_STREAM_PACKET_CONTEXT_TIMESTAMP_BEGIN,
	Q_STREAM_PACKET_CONTEXT_TIMESTAMP_END,
	Q_STREAM_PACKET_CONTEXT_EVENTS_DISCARDED,
	Q_STREAM_PACKET_CONTEXT_CONTENT_SIZE,
	Q_STREAM_PACKET_CONTEXT_PACKET_SIZE,
	Q_STREAM_PACKET_CONTEXT_PACKET_SEQ_NUM;

static
void __attribute__((constructor)) init_quarks(void)
{
	Q_STREAM_PACKET_CONTEXT_TIMESTAMP_BEGIN = g_quark_from_static_string("stream.packet.context.timestamp_begin");
	Q_STREAM_PACKET_CONTEXT_TIMESTAMP_END = g_quark_from_static_string("stream.packet.context.timestamp_end");
	Q_STREAM_PACKET_CONTEXT_EVENTS_DISCARDED = g_quark_from_static_string("stream.packet.context.events_discarded");
	Q_STREAM_PACKET_CONTEXT_CONTENT_SIZE = g_quark_from_static_string("stream.packet.context.content_size");
	Q_STREAM_PACKET_CONTEXT_PACKET_SIZE = g_quark_from_static_string("stream.packet.context.packet_size");
	Q_STREAM_PACKET_CONTEXT_PACKET_SEQ_NUM = g_quark_from_static_string("stream.packet.context.packet_seq_num");
}

static
struct ctf_callsite_dups *ctf_trace_callsite_lookup(struct ctf_trace *trace,
			GQuark callsite_name)
{
	return g_hash_table_lookup(trace->callsites,
			(gpointer) (unsigned long) callsite_name);
}

void bt_ctf_text_hook(void)
{
	/*
	 * Dummy function to prevent the linker from discarding this format as
	 * "unused" in static builds.
	 */
}

int print_field(struct bt_definition *definition)
{
	/* Print all fields in verbose mode */
	if (babeltrace_verbose)
		return 1;

	/* Filter out part of the packet context */
	if (definition->path == Q_STREAM_PACKET_CONTEXT_TIMESTAMP_BEGIN)
		return 0;
	if (definition->path == Q_STREAM_PACKET_CONTEXT_TIMESTAMP_END)
		return 0;
	if (definition->path == Q_STREAM_PACKET_CONTEXT_EVENTS_DISCARDED)
		return 0;
	if (definition->path == Q_STREAM_PACKET_CONTEXT_CONTENT_SIZE)
		return 0;
	if (definition->path == Q_STREAM_PACKET_CONTEXT_PACKET_SIZE)
		return 0;
	if (definition->path == Q_STREAM_PACKET_CONTEXT_PACKET_SEQ_NUM)
		return 0;

	return 1;
}

static
void set_field_names_print(struct ctf_text_stream_pos *pos, enum field_item item)
{
	switch (item) {
	case ITEM_SCOPE:
		if (opt_all_field_names || opt_scope_field_names)
			pos->print_names = 1;
		else
			pos->print_names = 0;
		break;
	case ITEM_HEADER:
		if (opt_all_field_names || opt_header_field_names)
			pos->print_names = 1;
		else
			pos->print_names = 0;
		break;
	case ITEM_CONTEXT:
		if (opt_all_field_names || opt_context_field_names)
			pos->print_names = 1;
		else
			pos->print_names = 0;
		break;
	case ITEM_PAYLOAD:
		if (opt_all_field_names || opt_payload_field_names)
			pos->print_names = 1;
		else
			pos->print_names = 0;

		break;
	default:
		assert(0);
	}
}

static
const char *print_loglevel(int value)
{
	switch (value) {
	case -1:
		return "";
	case BT_LOGLEVEL_EMERG:
		return "TRACE_EMERG";
	case BT_LOGLEVEL_ALERT:
		return "TRACE_ALERT";
	case BT_LOGLEVEL_CRIT:
		return "TRACE_CRIT";
	case BT_LOGLEVEL_ERR:
		return "TRACE_ERR";
	case BT_LOGLEVEL_WARNING:
		return "TRACE_WARNING";
	case BT_LOGLEVEL_NOTICE:
		return "TRACE_NOTICE";
	case BT_LOGLEVEL_INFO:
		return "TRACE_INFO";
	case BT_LOGLEVEL_DEBUG_SYSTEM:
		return "TRACE_DEBUG_SYSTEM";
	case BT_LOGLEVEL_DEBUG_PROGRAM:
		return "TRACE_DEBUG_PROGRAM";
	case BT_LOGLEVEL_DEBUG_PROCESS:
		return "TRACE_DEBUG_PROCESS";
	case BT_LOGLEVEL_DEBUG_MODULE:
		return "TRACE_DEBUG_MODULE";
	case BT_LOGLEVEL_DEBUG_UNIT:
		return "TRACE_DEBUG_UNIT";
	case BT_LOGLEVEL_DEBUG_FUNCTION:
		return "TRACE_DEBUG_FUNCTION";
	case BT_LOGLEVEL_DEBUG_LINE:
		return "TRACE_DEBUG_LINE";
	case BT_LOGLEVEL_DEBUG:
		return "TRACE_DEBUG";
	default:
		return "<<UNKNOWN>>";
	}
}

static
int ctf_text_write_event(struct bt_stream_pos *ppos, struct ctf_stream_definition *stream)
{
	struct ctf_text_stream_pos *pos =
		container_of(ppos, struct ctf_text_stream_pos, parent);
	struct ctf_stream_declaration *stream_class = stream->stream_class;
	int field_nr_saved;
	struct ctf_event_declaration *event_class;
	struct ctf_event_definition *event;
	uint64_t id;
	int ret;
	int dom_print = 0;

	id = stream->event_id;

	if (id >= stream_class->events_by_id->len) {
		fprintf(stderr, "[error] Event id %" PRIu64 " is outside range.\n", id);
		return -EINVAL;
	}
	event = g_ptr_array_index(stream->events_by_id, id);
	if (!event) {
		fprintf(stderr, "[error] Event id %" PRIu64 " is unknown.\n", id);
		return -EINVAL;
	}
	event_class = g_ptr_array_index(stream_class->events_by_id, id);
	if (!event_class) {
		fprintf(stderr, "[error] Event class id %" PRIu64 " is unknown.\n", id);
		return -EINVAL;
	}

	//
	// Check if this type of trace is in the table whitelist
	if (pos->table_fp) {
		struct bt_definition *definition = &event->event_fields->p;
		struct definition_struct *struct_definition = 
			container_of(definition, struct definition_struct, p);
		pos->task_event_name[0] = 0;
		bool is_task_name_found = false;
		bool is_event_name_found = false;
		unsigned long i;
		for (i = 0; i < struct_definition->fields->len; i++) {
			struct bt_definition *field =
				g_ptr_array_index(struct_definition->fields, i);
			
			if (strcmp(rem_(g_quark_to_string(field->name)), "taskNameField") == 0) {
				struct definition_string *string_definition =
					container_of(field, struct definition_string, p);
				while (strlen(string_definition->value) + 2 > pos->task_event_name_size) {
					pos->task_event_name_size *= 2;
					char * temp = realloc(pos->task_event_name, pos->task_event_name_size);
					if (temp == NULL) {
						fprintf(stderr, "ctf_text_write_event() realloc() returned null.\n");
						return -EINVAL;
					}
					pos->task_event_name = temp;
				}
				strcpy(pos->task_event_name, string_definition->value);
				strcat(pos->task_event_name, ".");
				is_task_name_found = true;
			}
			else if (strcmp(rem_(g_quark_to_string(field->name)), "eventNameField") == 0) {
				struct definition_string *string_definition =
					container_of(field, struct definition_string, p);
				while (strlen(string_definition->value) + 1 + strlen(pos->task_event_name) > pos->task_event_name_size) {
					pos->task_event_name_size *= 2;
					char * temp = realloc(pos->task_event_name, pos->task_event_name_size);
					if (temp == NULL) {
						fprintf(stderr, "ctf_text_write_event() realloc() returned null.\n");
						return -EINVAL;
					}
					pos->task_event_name = temp;
				}
				strcat(pos->task_event_name, string_definition->value);
				is_event_name_found = true;
			}
			if (is_task_name_found && is_event_name_found) {
				break;
			}
		}
		if (pos->is_event_whitelist(pos->table_whitelist, pos->task_event_name)) {
			pos->is_this_event_whitelisted = true;
		}
		else {
			pos->is_this_event_whitelisted = false;
		}
	}
	//

	handle_debug_info_event(stream_class, event);

	if (stream->has_timestamp) {
		set_field_names_print(pos, ITEM_HEADER);
		if (pos->print_names)
			// pos->print_all(pos, "timestamp = ");
			fprintf(pos->fp, "timestamp = ");
		// else
		// 	fprintf(pos->fp, "[");
		if (opt_clock_cycles) {
			ctf_print_timestamp(pos->fp, stream, stream->cycles_timestamp);
			//
			if (pos->is_this_event_whitelisted) {
				ctf_print_timestamp(pos->table_fp, stream, stream->cycles_timestamp);
			}
			//
		} else {
			ctf_print_timestamp(pos->fp, stream, stream->real_timestamp);
			//
			if (pos->is_this_event_whitelisted) {
				ctf_print_timestamp(pos->table_fp, stream, stream->real_timestamp);
			}
			//
		}
		// if (!pos->print_names)
		// 	fprintf(pos->fp, "]");

		if (pos->print_names)
			pos->print_all(pos, ", ");
			// fprintf(pos->fp, ", ");
		else
			pos->print_all(pos, ",");
			// fprintf(pos->fp, ",");
	}
	if (opt_delta_field && stream->has_timestamp) {
		uint64_t delta, delta_sec, delta_nsec;

		set_field_names_print(pos, ITEM_HEADER);
		if (pos->print_names)
			fprintf(pos->fp, "delta = ");
		else
			fprintf(pos->fp, "(");
		if (pos->last_real_timestamp != -1ULL) {
			delta = stream->real_timestamp - pos->last_real_timestamp;
			delta_sec = delta / NSEC_PER_SEC;
			delta_nsec = delta % NSEC_PER_SEC;
			fprintf(pos->fp, "+%" PRIu64 ".%09" PRIu64,
				delta_sec, delta_nsec);
		} else {
			fprintf(pos->fp, "+?.?????????");
		}
		if (!pos->print_names)
			fprintf(pos->fp, ")");

		if (pos->print_names)
			fprintf(pos->fp, ", ");
		else
			fprintf(pos->fp, " ");
		pos->last_real_timestamp = stream->real_timestamp;
		pos->last_cycles_timestamp = stream->cycles_timestamp;
	}

	if ((opt_trace_field || opt_all_fields) && stream_class->trace->parent.path[0] != '\0') {
		set_field_names_print(pos, ITEM_HEADER);
		if (pos->print_names) {
			fprintf(pos->fp, "trace = ");
		}
		fprintf(pos->fp, "%s", stream_class->trace->parent.path);
		if (pos->print_names)
			fprintf(pos->fp, ", ");
		else
			fprintf(pos->fp, " ");
	}
	if ((opt_trace_hostname_field || opt_all_fields || opt_trace_default_fields)
			&& stream_class->trace->env.hostname[0] != '\0') {
		set_field_names_print(pos, ITEM_HEADER);
		if (pos->print_names) {
			fprintf(pos->fp, "trace:hostname = ");
		}
		fprintf(pos->fp, "%s", stream_class->trace->env.hostname);
		if (pos->print_names)
			fprintf(pos->fp, ", ");
		dom_print = 1;
	}
	if ((opt_trace_domain_field || opt_all_fields) && stream_class->trace->env.domain[0] != '\0') {
		set_field_names_print(pos, ITEM_HEADER);
		if (pos->print_names) {
			fprintf(pos->fp, "trace:domain = ");
		} else if (dom_print) {
			fprintf(pos->fp, ":");
		}
		fprintf(pos->fp, "%s", stream_class->trace->env.domain);
		if (pos->print_names)
			fprintf(pos->fp, ", ");
		dom_print = 1;
	}
	if ((opt_trace_procname_field || opt_all_fields || opt_trace_default_fields)
			&& stream_class->trace->env.procname[0] != '\0') {
		set_field_names_print(pos, ITEM_HEADER);
		if (pos->print_names) {
			fprintf(pos->fp, "trace:procname = ");
		} else if (dom_print) {
			fprintf(pos->fp, ":");
		}
		fprintf(pos->fp, "%s", stream_class->trace->env.procname);
		if (pos->print_names)
			fprintf(pos->fp, ", ");
		dom_print = 1;
	}
	if ((opt_trace_vpid_field || opt_all_fields || opt_trace_default_fields)
			&& stream_class->trace->env.vpid != -1) {
		set_field_names_print(pos, ITEM_HEADER);
		if (pos->print_names) {
			fprintf(pos->fp, "trace:vpid = ");
		} else if (dom_print) {
			fprintf(pos->fp, ":");
		}
		fprintf(pos->fp, "%d", stream_class->trace->env.vpid);
		if (pos->print_names)
			fprintf(pos->fp, ", ");
		dom_print = 1;
	}
	if ((opt_loglevel_field || opt_all_fields) && event_class->loglevel != -1) {
		set_field_names_print(pos, ITEM_HEADER);
		if (pos->print_names) {
			fprintf(pos->fp, "loglevel = ");
		} else if (dom_print) {
			fprintf(pos->fp, ":");
		}
        char * loglevel_str;
        switch (event_class->loglevel)
        {
            case 1:
                loglevel_str = "Silent";
                break;
            case 2:
                loglevel_str = "Critical";
                break;
            case 3:
                loglevel_str = "Error";
                break;
            case 4:
                loglevel_str = "Warning";
                break;
            case 6:
                loglevel_str = "Info";
                break;
            case 7:
                loglevel_str = "Noise";
                break;
            case 13:
                loglevel_str = "All";
                break;
            default:
                loglevel_str = "Unknown";
                break;
        }
        pos->print_all(pos, "%s,", loglevel_str);
        // fprintf(pos->fp, "%s,", loglevel_str);
		// fprintf(pos->fp, "%s (%d)",
		// 	print_loglevel(event_class->loglevel),
		// 	event_class->loglevel);
		if (pos->print_names)
			pos->print_all(pos, ", ");
			// fprintf(pos->fp, ", ");
		dom_print = 1;
	}
	if ((opt_emf_field || opt_all_fields) && event_class->model_emf_uri) {
		set_field_names_print(pos, ITEM_HEADER);
		if (pos->print_names) {
			fprintf(pos->fp, "model.emf.uri = ");
		} else if (dom_print) {
			fprintf(pos->fp, ":");
		}
		fprintf(pos->fp, "\"%s\"",
			g_quark_to_string(event_class->model_emf_uri));
		if (pos->print_names)
			fprintf(pos->fp, ", ");
		dom_print = 1;
	}
	if ((opt_callsite_field || opt_all_fields)) {
		struct ctf_callsite_dups *cs_dups;
		struct ctf_callsite *callsite;

		cs_dups = ctf_trace_callsite_lookup(stream_class->trace,
				event_class->name);
		if (cs_dups) {
			int i = 0;

			set_field_names_print(pos, ITEM_HEADER);
			if (pos->print_names) {
				fprintf(pos->fp, "callsite = ");
			} else if (dom_print) {
				fprintf(pos->fp, ":");
			}
			fprintf(pos->fp, "[");
			bt_list_for_each_entry(callsite, &cs_dups->head, node) {
				if (i != 0)
					fprintf(pos->fp, ",");
				if (CTF_CALLSITE_FIELD_IS_SET(callsite, ip)) {
					fprintf(pos->fp, "%s@0x%" PRIx64 ":%s:%" PRIu64 "",
						callsite->func, callsite->ip, callsite->file,
						callsite->line);
				} else {
					fprintf(pos->fp, "%s:%s:%" PRIu64 "",
						callsite->func, callsite->file,
						callsite->line);
				}
				i++;
			}
			fprintf(pos->fp, "]");
			if (pos->print_names)
				fprintf(pos->fp, ", ");
			dom_print = 1;
		}
	}
	// if (dom_print && !pos->print_names)
	// 	fprintf(pos->fp, " ");
	// set_field_names_print(pos, ITEM_HEADER);
	// if (pos->print_names)
	// 	fprintf(pos->fp, "name = ");
	// fprintf(pos->fp, "%s", g_quark_to_string(event_class->name));
	// if (pos->print_names)
	// 	pos->field_nr++;
	// else
	// 	fprintf(pos->fp, ":");

	/* print cpuid field from packet context */
	// if (stream->stream_packet_context) {
	// 	if (pos->field_nr++ != 0)
	// 		fprintf(pos->fp, ",");
	// 	set_field_names_print(pos, ITEM_SCOPE);
	// 	if (pos->print_names)
	// 		fprintf(pos->fp, " stream.packet.context =");
	// 	field_nr_saved = pos->field_nr;
	// 	pos->field_nr = 0;
	// 	set_field_names_print(pos, ITEM_CONTEXT);
	// 	ret = generic_rw(ppos, &stream->stream_packet_context->p);
	// 	if (ret)
	// 		goto error;
	// 	pos->field_nr = field_nr_saved;
	// }

	/* Only show the event header in verbose mode */
	if (babeltrace_verbose && stream->stream_event_header) {
		if (pos->field_nr++ != 0)
			fprintf(pos->fp, ",");
		set_field_names_print(pos, ITEM_SCOPE);
		if (pos->print_names)
			fprintf(pos->fp, " stream.event.header =");
		field_nr_saved = pos->field_nr;
		pos->field_nr = 0;
		set_field_names_print(pos, ITEM_CONTEXT);
		ret = generic_rw(ppos, &stream->stream_event_header->p);
		if (ret)
			goto error;
		pos->field_nr = field_nr_saved;
	}

	/* print stream-declared event context */
	if (stream->stream_event_context) {
		if (pos->field_nr++ != 0)
			fprintf(pos->fp, ",");
		set_field_names_print(pos, ITEM_SCOPE);
		if (pos->print_names)
			fprintf(pos->fp, " stream.event.context =");
		field_nr_saved = pos->field_nr;
		pos->field_nr = 0;
		set_field_names_print(pos, ITEM_CONTEXT);
		ret = generic_rw(ppos, &stream->stream_event_context->p);
		if (ret)
			goto error;
		pos->field_nr = field_nr_saved;
	}

	/* print event-declared event context */
	if (event->event_context) {
		if (pos->field_nr++ != 0)
			fprintf(pos->fp, ",");
		set_field_names_print(pos, ITEM_SCOPE);
		if (pos->print_names)
			fprintf(pos->fp, " event.context =");
		field_nr_saved = pos->field_nr;
		pos->field_nr = 0;
		set_field_names_print(pos, ITEM_CONTEXT);
		ret = generic_rw(ppos, &event->event_context->p);
		if (ret)
			goto error;
		pos->field_nr = field_nr_saved;
	}

	/* Read and print event payload */
	if (event->event_fields) {
		if (pos->field_nr++ != 0)
			pos->print_all(pos, ",");
			// fprintf(pos->fp, ",");
		set_field_names_print(pos, ITEM_SCOPE);
		if (pos->print_names)
			fprintf(pos->fp, " event.fields =");
		field_nr_saved = pos->field_nr;
		pos->field_nr = 0;
		set_field_names_print(pos, ITEM_PAYLOAD);
		ret = generic_rw(ppos, &event->event_fields->p);
		if (ret)
			goto error;
		pos->field_nr = field_nr_saved;
	}
	/* newline */
	pos->print_all(pos, "\r\n");
	// fprintf(pos->fp, "\r\n");
	pos->field_nr = 0;

	return 0;

error:
	fprintf(stderr, "[error] Unexpected end of stream. Either the trace data stream is corrupted or metadata description does not match data layout.\n");
	return ret;
}

//
static int read_table_config(const char *table_config_path, GHashTable *table_whitelist) {
	FILE * config = fopen(table_config_path, "r");
	if (config == NULL) {
		fprintf(stderr, "Table config file not found.\n");
		return -1;
	}
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	while ((read = getline(&line, &len, config)) != -1) {
		char *token = strtok(line, ":");
		if (token) {
			char *token_copy = (char *) malloc(strlen(token) + 1);
			strcpy(token_copy, token);
			g_hash_table_insert(table_whitelist, token_copy, NULL);
		}
		else {
			fprintf(stderr, "Error parsing table configs, skipping.\n");
		}
		free(line);
		line = NULL;
		len = 0;
	}
	free(line);
	line = NULL;
	len = 0;
	if (fclose(config)) {
		perror("Error on fclose");
		return -1;
	}
	return 0;
}

// testing use
static void printKeyValue(gpointer key, gpointer value, gpointer userData) {
	char *realKey = (char *)key;
	char *realValue = (char *)value;
	printf("%s => %s\n", realKey, realValue);
}
//

static
struct bt_trace_descriptor *ctf_text_open_trace(const char *path,
		//
		const char *table_config_path,
		const char *table_path,
		//
		int flags,
		void (*packet_seek)(struct bt_stream_pos *pos, size_t index,
			int whence), FILE *metadata_fp)
{
	struct ctf_text_stream_pos *pos;
	FILE *fp;

	pos = g_new0(struct ctf_text_stream_pos, 1);
	if (!pos) {
		goto error;
	}
	init_trace_descriptor(&pos->trace_descriptor);

	pos->last_real_timestamp = -1ULL;
	pos->last_cycles_timestamp = -1ULL;
	switch (flags & O_ACCMODE) {
	case O_RDWR:
		if (!path)
			fp = stdout;
		else
			fp = fopen(path, "w");
		if (!fp)
			goto error;
		pos->fp = fp;
		//
		pos->table_whitelist = NULL;
		pos->table_fp = NULL;
		pos->print_all = print_all;
		pos->is_this_event_whitelisted = false;
		if (table_config_path) {
			pos->table_whitelist = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
			int err = read_table_config(table_config_path, pos->table_whitelist);
			if (err)
				goto error;
			pos->table_fp = fopen(table_path, "w");
			pos->is_event_whitelist = is_event_whitelist;
			// g_hash_table_foreach(pos->table_whitelist, printKeyValue, NULL);
			pos->task_event_name_size = 200;
			pos->task_event_name = malloc(sizeof(char) * pos->task_event_name_size);// allocate more if needed later
			if (pos->task_event_name == NULL) {
				fprintf(stderr, "ctf_text_open_trace() malloc() returned null.\n");
				goto error;
			}
			pos->task_event_name[0] = 0;
		}
		//
		pos->parent.rw_table = write_dispatch_table;
		pos->parent.event_cb = ctf_text_write_event;
		pos->parent.trace = &pos->trace_descriptor;
		pos->print_names = 0;
		babeltrace_ctf_console_output++;
		break;
	case O_RDONLY:
	default:
		fprintf(stderr, "[error] Incorrect open flags.\n");
		goto error;
	}

	return &pos->trace_descriptor;
error:
	g_free(pos);
	return NULL;
}

static
int ctf_text_close_trace(struct bt_trace_descriptor *td)
{
	int ret;
	struct ctf_text_stream_pos *pos =
		container_of(td, struct ctf_text_stream_pos, trace_descriptor);

	babeltrace_ctf_console_output--;
	if (pos->fp != stdout) {
		ret = fclose(pos->fp);
		if (ret) {
			perror("Error on fclose");
			return -1;
		}
	}
	//
	if (pos->table_fp) {
		ret = fclose(pos->table_fp);
		if (ret) {
			perror("Error on fclose");
			return -1;
		}
	}
	if (pos->table_whitelist) {
		g_hash_table_destroy(pos->table_whitelist);
	}
	if (pos->task_event_name_size > 0) {
		free(pos->task_event_name);
		pos->task_event_name = 0;
		pos->task_event_name_size = 0;
	}
	//
	g_free(pos);
	return 0;
}

static
void __attribute__((constructor)) ctf_text_init(void)
{
	int ret;

	ctf_text_format.name = g_quark_from_static_string("text");
	ret = bt_register_format(&ctf_text_format);
	assert(!ret);
}

static
void __attribute__((destructor)) ctf_text_exit(void)
{
	bt_unregister_format(&ctf_text_format);
}
