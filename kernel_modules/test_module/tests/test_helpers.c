/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is offered under two licenses GPLv2 and Apache License Version 2.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

#include "test_helpers.h"
#include <stdio.h>
#include <stdlib.h>

#include <linux/errno.h>
struct bpf_object *load_obj_or_exit(char *path) {
	struct bpf_object *obj = bpf_object__open(path);
	if (!obj || libbpf_get_error(obj)) {
		puts("Could not open object");
		exit(EXIT_FAILURE);
	}
	int ret = bpf_object__load(obj);
	if (ret) {
		puts("Could not load object");
		exit(EXIT_FAILURE);
	}
	return obj;
}

struct bpf_program *find_program_by_name_or_exit(struct bpf_object *obj, char *name) {
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
	if (!prog || libbpf_get_error(prog)) {
		puts("Could not select program from file");
        exit(EXIT_FAILURE);
	}
	return prog;
}

struct perf_buffer *setup_perf_events_cb(struct bpf_object *obj, 
					char *map_name,size_t buff_pages, struct perf_buffer_opts *opts) {
	struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
	if (!map || libbpf_get_error(map)) {
		puts("Could not select perf evnets map from file");
        exit(EXIT_FAILURE);
	}
	struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(map), buff_pages, opts);
	if (!pb || libbpf_get_error(pb)) {
		puts("Could not register perf event callbacks");
		exit(EXIT_FAILURE);
	}
	return pb;
}

int find_map_fd_by_name_or_exit(struct bpf_object *obj, const char *map_name) {
	struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
	if (!map || libbpf_get_error(map)) {
		puts("Could not select perf evnets map from file");
        exit(EXIT_FAILURE);
	}
    return bpf_map__fd(map);
}
