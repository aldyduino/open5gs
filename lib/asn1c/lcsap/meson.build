libasn1c_lcsap_inc = include_directories('.')
libasn1c_lcsap_sources = files(run_command(
    'find', meson.current_source_dir(), '-maxdepth', '1', '-type', 'f',
    '-name', 'LCSAP_*.c').stdout().strip().split('\n'))

libasn1c_lcsap_chunk_size = 400
libasn1c_lcsap_static_libs = []
libasn1c_lcsap_chunk_sources = []
libasn1c_lcsap_chunk_index = 0

foreach source : libasn1c_lcsap_sources
    libasn1c_lcsap_chunk_sources += [source]

    if libasn1c_lcsap_chunk_sources.length() == libasn1c_lcsap_chunk_size
        libasn1c_lcsap_static_libs += [static_library(
            'ogsasn1c-lcsap-@0@'.format(libasn1c_lcsap_chunk_index),
            sources : libasn1c_lcsap_chunk_sources,
            c_args : libasn1c_common_cc_flags,
            include_directories : libasn1c_lcsap_inc,
            dependencies : [libasn1c_common_dep, libasn1c_util_dep],
            pic : true,
            install : false)]

        libasn1c_lcsap_chunk_sources = []
        libasn1c_lcsap_chunk_index += 1
    endif
endforeach

if libasn1c_lcsap_chunk_sources.length() > 0
    libasn1c_lcsap_static_libs += [static_library(
        'ogsasn1c-lcsap-@0@'.format(libasn1c_lcsap_chunk_index),
        sources : libasn1c_lcsap_chunk_sources,
        c_args : libasn1c_common_cc_flags,
        include_directories : libasn1c_lcsap_inc,
        dependencies : [libasn1c_common_dep, libasn1c_util_dep],
        pic : true,
        install : false)]
endif

libasn1c_lcsap = library('ogsasn1c-lcsap',
    version : libogslib_version,
    include_directories : libasn1c_lcsap_inc,
    dependencies : [libasn1c_common_dep, libasn1c_util_dep],
    link_whole : libasn1c_lcsap_static_libs,
    install : true)

libasn1c_lcsap_dep = declare_dependency(
    link_with : libasn1c_lcsap,
    include_directories : libasn1c_lcsap_inc,
    dependencies : [libasn1c_common_dep, libasn1c_util_dep])