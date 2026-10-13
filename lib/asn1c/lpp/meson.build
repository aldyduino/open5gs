libasn1c_lpp_inc = include_directories('.')
libasn1c_lpp_sources = files(run_command(
    'find', meson.current_source_dir(), '-maxdepth', '1', '-type', 'f',
    '-name', 'LPP_*.c').stdout().strip().split('\n'))
libasn1c_lpp_c_args = libasn1c_common_cc_flags + ['-UASN_DISABLE_UPER_SUPPORT']

libasn1c_lpp_chunk_size = 400
libasn1c_lpp_static_libs = []
libasn1c_lpp_chunk_sources = []
libasn1c_lpp_chunk_index = 0

foreach source : libasn1c_lpp_sources
    libasn1c_lpp_chunk_sources += [source]

    if libasn1c_lpp_chunk_sources.length() == libasn1c_lpp_chunk_size
        libasn1c_lpp_static_libs += [static_library(
            'ogsasn1c-lpp-@0@'.format(libasn1c_lpp_chunk_index),
            sources : libasn1c_lpp_chunk_sources,
            c_args : libasn1c_lpp_c_args,
            include_directories : libasn1c_lpp_inc,
            dependencies : [libasn1c_common_dep, libasn1c_util_dep],
            pic : true,
            install : false)]

        libasn1c_lpp_chunk_sources = []
        libasn1c_lpp_chunk_index += 1
    endif
endforeach

if libasn1c_lpp_chunk_sources.length() > 0
    libasn1c_lpp_static_libs += [static_library(
        'ogsasn1c-lpp-@0@'.format(libasn1c_lpp_chunk_index),
        sources : libasn1c_lpp_chunk_sources,
        c_args : libasn1c_lpp_c_args,
        include_directories : libasn1c_lpp_inc,
        dependencies : [libasn1c_common_dep, libasn1c_util_dep],
        pic : true,
        install : false)]
endif

libasn1c_lpp = library('ogsasn1c-lpp',
    version : libogslib_version,
    include_directories : libasn1c_lpp_inc,
    dependencies : [libasn1c_common_dep, libasn1c_util_dep],
    link_whole : libasn1c_lpp_static_libs,
    install : true)

libasn1c_lpp_dep = declare_dependency(
    link_with : libasn1c_lpp,
    include_directories : libasn1c_lpp_inc,
    dependencies : [libasn1c_common_dep, libasn1c_util_dep])