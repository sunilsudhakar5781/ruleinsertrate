project('rule_insert_rate', ['c','cpp'], default_options: ['buildtype=debug'])

add_project_arguments('-DDOCA_ALLOW_EXPERIMENTAL_API -lpthread', language: ['c', 'cpp'])

source_files = [
        'src/main.c',
        'src/insert_del.c',
        'src/flow_common.c',
        'src/dpdk_utils.c',
]

deps = [
        dependency('doca-flow'),
        dependency('doca-argp'),
        dependency('doca-common'),
        dependency('libdpdk'),
]

app_inc_dirs = [
        include_directories('src'),
]

executable(
        'rule_insert_rate',
        source_files,
        dependencies: deps,
        include_directories: app_inc_dirs
)
