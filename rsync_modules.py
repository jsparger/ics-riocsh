#!/usr/bin/env python2.7
#
# ---EPICS Environment Manager
# ---Copyright (C) 2015 Cosylab
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""This script is based on get_prerequisites.py
It tries to rsync required modules specified either on the command line (iocsh syntax)
or in snippets loaded via requireSnippet() or '<' redirection.
"""

from __future__ import print_function
import argparse
import os
import re
import logging
import subprocess
from shlex import split as shlex_split

from sys import path as sys_path
try:
    sys_path.append(os.path.abspath(os.environ['EPICS_ENV_PATH']))
except KeyError:
    # IOC Factory generates a different environment
    sys_path.append(os.path.abspath(os.path.join(os.environ['EPICS_MODULES_PATH'], 'environment', os.environ['ENVIRONMENT_VERSION'], os.environ['BASE'], 'bin', os.environ['EPICS_HOST_ARCH'])))
from check_excludes import module_match

args  = None
rsync = None

def module_key(version):
    """Key for sorting module versions with python built-in sorting algorithms."""
    ver = parse_semver(version)
    if ver:
        if ver['prerelease']:
            matches = re.search(r'ESS([\d]+)', ver['prerelease'])
            if matches:
                try:
                    ess_num = int(matches.group(1))
                    return (ver['major'], ver['minor'], ver['patch'], 1, ess_num)
                except ValueError:
                    pass
            return (ver['major'], ver['minor'], ver['patch'], 0, 0)
        else:
            return (ver['major'], ver['minor'], ver['patch'], 1, 0)
    return (0, 0, 0, 0, 0)




class RSYNC(object):
    def __init__(self, prefix, epicsbase, arch):
        self._synced        = set()
        self._prefix        = prefix.rstrip(os.path.sep)
        self._rsync_host    = 'owncloud01.esss.lu.se:80'
        self._rsync_opts    = '-v --recursive --timeout 120 --perms --links --times --prune-empty-dirs --relative ' \
                              '--include={epicsbase}/lib/{arch}** --exclude=*/lib/** ' \
                              '--include={epicsbase}/bin/{arch}** --exclude=*/bin/** ' \
                              '--include={epicsbase}/dbd/**       --exclude=*/dbd/** ' \
                              '--include={epicsbase}/include/**   --exclude=*/include/**'.format(arch = arch, epicsbase = epicsbase)
        self._deprsync_opts = '-v --recursive --timeout 120 --perms --links --times --prune-empty-dirs --relative ' \
                              '-f"+ {epicsbase}/lib/{arch}" -f"- lib/*" ' \
                              '-f"+ */" -f"+ /**.dep" -f"- *"'.format(arch = arch, epicsbase = epicsbase)


    def rsync_deps(self, module = ""):
        # rsync every dep file for all versions of a module. or all modules
        if module == "":
            logger = logging.getLogger(__name__)
            logger.log(logger.getEffectiveLevel(), 'Updating dependency files (this might take a while)...')

        if self._rsync(os.path.join('epics/modules', os.path.basename(module)), os.path.dirname(self._prefix), self._deprsync_opts):
            raise RuntimeError('Cannot update dependency files')

        if module == "":
            logger.log(logger.getEffectiveLevel(), 'Done')


    def _rsync(self, src, dst, rsync_opts = None):
        if rsync_opts is None:
            rsync_opts = self._rsync_opts
        logger = logging.getLogger(__name__)
        logger.debug("rsync {rsync_opts} 'rsync://{rsync_host}/{src}' '{dst}'".format(rsync_opts = rsync_opts, rsync_host = self._rsync_host, src = src, dst = dst))
        return subprocess.call(shlex_split("rsync {rsync_opts} 'rsync://{rsync_host}/{src}' '{dst}'".format(rsync_opts = rsync_opts, rsync_host = self._rsync_host, src = src, dst = dst)))


    def rsync_snippet(self, src):
        if self._rsync('epics/modules/' + src.replace(os.path.sep, '/'), os.path.dirname(self._prefix)) == 0:
            return os.path.join(self._prefix, src)
        else:
            return None


    def rsync_module(self, module, version):
        if (module, version) in self._synced:
            logging.getLogger(__name__).debug('Already rsynced: {},{}'.format(module, version))
            return
        if (self._rsync('epics/modules/{}/{}'.format(module, version), os.path.dirname(self._prefix)) == 0):
            self._synced.add((module, version))
        else:
            raise RuntimeError('Cannot rsync {},{}'.format(module, version))




class DependencyResolver(object):
    """Finds EPICS modules dependencies by looking at
    *  the included headers
    *  included templates in substitution files
    *  record types and device support usage in template files.
    """

    def __init__(self, files, prefix, eb_version, ta, ud, req_snippets = []):
        logger = logging.getLogger(__name__)
        logger.info('Dependency resolver for {}'.format(files))

        self._prefix = prefix
        self._eb_version = eb_version
        self._ta = ta
        self._ud = []
        self._required_snippets = set()
        self._dependencies = set()
        self._epicsenv = dict()
        self._derefed_macros = set()
        self._macro_deref_pattern = re.compile("(?<=\$[{\(])([a-zA-Z]*)(?=[}\)])")

        for rs in req_snippets:
            rs = self.check_for_requireSnippet(rs)
            if rs is not None:
                self._required_snippets.add(rs)

        # Convert user dependency to (module, version) tuple
        for udm in ud:
            tmp = udm.rsplit(',', 1)
            if len(tmp) != 2:
                raise RuntimeError('User dependency: module,version')
            self._ud.append((tmp[0], tmp[1]))

        if isinstance(files, str):
            files = [ files ]

        for name in files:
            if os.path.isfile(name):
                logger.debug('Parsing "{}" as st.cmd'.format(name))
                self.parse_snippet(name)
            else:
                modver = name.split(',')
                if len(modver) != 2:
                   raise RuntimeError('module,version')

                self._ud.append((modver[0], modver[1]))

        while True:
            self.resolve_module(self._ud)

            if len(self._required_snippets) == 0:
                break

            self.parse_snippet(None, self.resolve_snippets())


    def resolve_module(self, module):
        if isinstance(module, tuple):
            module = [ module ]

        module = self.resolve_versions(module)

        while module != []:
            mod_ver = module.pop()
            self._dependencies |= recursive_solve(mod_ver, args)

        self.rsync_modules()


    def strip_quote(self, quoted):
        quoted = quoted.strip()
        if quoted[0] in ['"', "'"]:
            quoted = quoted.strip(quoted[0])

        return quoted

    def extract_macro_def(self, macro_defs):
        macrostr = self.strip_quote(macro_defs.strip())

        macros = dict()
        for macro in macrostr.split(','):
            (m, v) = macro.split('=')
            macros[m.strip()] = v.strip()

        return list(macros.iteritems())


    def extract_epicsenv(self, epicsenv):
        envtp = epicsenv.split('(')[1][:-1].split(',', 1)

        m = self.strip_quote(envtp[0])
        v = self.strip_quote(envtp[1])

        return (m, v)

    def check_for_requireSnippet(self, cmd):
        """
           Check for requireSnippet(snippet[, macros]) in 'cmd' and return a (snippet, ((macro, value), (macro, value))) tuple
            cannot use [(m,v), (m,v)] because it needs to be hashable
        """
        cmd = cmd.strip().strip('"\'').rstrip(')')
        if cmd.startswith('requireSnippet'):
            snippet   = cmd.replace('requireSnippet(', '').split(',', 1)
            iocshLoad = False
        elif cmd.startswith('iocshLoad'):
            snippet   = cmd.replace('iocshLoad(', '').split(',', 1)
            iocshLoad = True
            # return for now. iocshLoad() has to use absolute pathnames or files in the current directory
            # and I don't know how to make sure that it is indeed an EEE snippet
            return None
        else:
            return None

        if len(snippet) == 1:
            snippet = snippet[0]
            macros  = []
        else:
            macros = self.extract_macro_def(snippet[1])
            snippet = snippet[0].strip().strip('"\'')

        logging.getLogger(__name__).debug('Found requireSnippet {}'.format(snippet))
        return (snippet, tuple(macros))


    def resolve_versions(self, modules):
        logger = logging.getLogger(__name__)

        resolved = []
        while modules != []:
            (modulename, moduleversion) = modules.pop()
            logger.debug('Resolving {},{}...'.format(modulename, moduleversion))
            moduleversion = module_version(
                modulename,
                comp_version=moduleversion,
                epics_base_version=self._eb_version,
                target_arch=self._ta
            )
            if re.search(r'[^A-Za-z0-9_]', modulename):
                logger.warning('Library {} contains unsupported characters'.format(modulename))
            logger.debug('Resolved to {},{}...'.format(modulename, moduleversion))
            resolved.append((modulename, moduleversion))

        return resolved


    def rsync_modules(self, modules = None):
        logger = logging.getLogger(__name__)
        if modules is None:
            modules = self._dependencies
        if isinstance(modules, tuple):
            modules = [ modules ]
        for (modname, modversion) in modules:
            rsync.rsync_module(modname, modversion)


    def parse_snippet(self, snippet, snippets = []):
        logger = logging.getLogger(__name__)
        if snippet is not None:
            subs = [ '${}', '$({})', '${{{}}}' ]
            if len(snippet) == 2:
                macros  = snippet[1]
                snippet = snippet[0]
            else:
                macros = []

            with open(snippet, 'r') as cmd:
                for line in cmd:

                    line = line.strip()
                    if line == '' or line[0] == '#':
                        continue

                    # find macro dereference:
                    self._derefed_macros.update(self._macro_deref_pattern.findall())

                    # substitute macros
                    for macro in macros:
                        for sub in subs:
                            line = line.replace(sub.format(macro[0]), macro[1])

                    # restrip and recheck after macro substitution
                    line = line.strip().strip('"\'')
                    if line.startswith('#') or line == '':
                        continue

                    # handle epicsEnvSet(). it is heavily used by IOCFactory
                    if line.startswith('epicsEnvSet'):
                        (m, v) = self.extract_epicsenv(line)
                        self._epicsenv[m] = v

                    # note the space after require! Needed to prevent matching requireSnippets
                    if line.startswith('require '):
                        (module, version) = line.split('require ')[1].split(',')
                        logger.debug('Found {},{}'.format(module, version))
                        self.resolve_module((module.strip(), version.strip()))
                        continue

                    rs = self.check_for_requireSnippet(line)
                    if rs is not None:
                        self._required_snippets.add(rs)
                        continue

                    if line.startswith('<'):
                        # IOCFactory does this
                        line = line[1:].strip().replace('/opt/epics/modules/', '')
                        logger.debug('Rsyncing ' + line)
                        snippets.append((rsync.rsync_snippet(line), tuple(list(self._epicsenv.iteritems()))))

        while snippets != []:
            self.parse_snippet(snippets.pop(), snippets)


    def resolve_snippets(self):
        """Search all required modules for snippets
        """
        logger = logging.getLogger(__name__)
        snippets = dict()
        while len(self._required_snippets):
            (snippet, macros) = self._required_snippets.pop()
            logger.debug('Looking for snippet {}...'.format(snippet))
            for (required_module, required_version) in self._dependencies:
                snippet_path = os.path.join(self._prefix, required_module, required_version, 'startup', snippet)
                if not os.path.isfile(snippet_path):
                    continue # Sanity check
                if snippets.has_key(snippet) and snippets[snippet][0] != snippet_path:
                    raise RuntimeError('{} is found in (at least) two different places: {} and {}'.format(snippet, snippets[snippet][0], snippet_path))
                logger.debug('Found snippet as {}'.format(snippet_path))
                snippets[snippet] = (snippet_path, macros)
                break

            if not snippets.has_key(snippet):
                raise RuntimeError('Could not find snippet {}'.format(snippet))

        return snippets.values()

    def add_dependency(self, modulename):
        """Add modulename to list of dependencies."""
        logger = logging.getLogger(__name__)
        if modulename in [module.rsplit(',', 1)[0] for module in self._ud]:
            return # Module was already manually listed
        self._dependencies.add(
            (
                modulename,
                module_version(
                    modulename,
                    epics_base_version=self._eb_version,
                    target_arch=self._ta
                )
            )
        )
        logger.info('Found dependency on {}'.format(modulename))




def parse_semver(version):
    """Parses a semantic version string into a dict"""
    metadata = None
    prerelease = None
    if '+' in version:
        (version, metadata) = version.rsplit('+', 1)
    if '-' in version:
        (version, prerelease) = version.split('-', 1)
    matches = re.match(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$', version)
    if matches and len(matches.groups()) == 3:
        try:
            return {
                'major': int(matches.group(1)),
                'minor': int(matches.group(2)),
                'patch': int(matches.group(3)),
                'prerelease': prerelease,
                'metadata': metadata,
            }
        except ValueError:
            return None
    return None


#FIXME: let this one call require.c. don't reinvent the wheel
def module_version(module, comp_version='', epics_base_version='', target_arch=''):
    """Look for version in the following order:
    1. Architecture dependent default file
    2. Architecture independent default file
    3. Exact match with comp_version
    4. Highest installed version.
    """
    logger = logging.getLogger(__name__)
    try:
        epics_base = os.path.join(os.environ['EPICS_BASES_PATH'], 'base-{}'.format(epics_base_version))
    except KeyError:
        epics_base = os.environ['EPICS_BASE']

    arch_default = os.path.join(epics_base, 'configure', 'default.{}.dep'.format(target_arch))
    if os.path.isfile(arch_default):
        version = search_dep_file(arch_default, module)
        if version:
            return version

    epics_default = os.path.join(epics_base, 'configure', 'default.dep')
    if os.path.isfile(epics_default):
        version = search_dep_file(epics_default, module)
        if version:
            return version

    installed_versions = set()
    module_dir = os.path.join(args.prefix, module)
    if not os.path.isdir(module_dir):
        rsync.rsync_deps(module_dir)

    if os.path.isdir(module_dir):
        for version in os.listdir(module_dir):
            depfile = os.path.join(module_dir, version, epics_base_version, 'lib',
                                   target_arch, '{}.dep'.format(module))
            if os.path.isfile(depfile):
                if comp_version == version:
                    return version
                if parse_semver(version):
                    installed_versions.add(version)

    if installed_versions:
        sorted_installed_versions = sorted(installed_versions, key=module_key)
        for version in reversed(sorted_installed_versions):
            if module_match(comp_version, version):
                return version

    logger.error('No version found for module {}'.format(module))
    raise RuntimeError('No version found for module {}'.format(module))


def search_dep_file(depfile, module):
    """depfile should contain lines of '<module>,<version>'."""
    with open(depfile, 'r') as filehandler:
        for line in filehandler:
            lsplit = line.strip().rsplit(',', 1)
            if lsplit[0] == module:
                return lsplit[1]
    return None


def recursive_solve(module, args, depth=10):
    """Recursive solve is only implemented for headers."""
    logger = logging.getLogger(__name__)
    logger.info('Looking up deps for {} {} depth {}'.format(module[0], module[1], depth))
    if depth == 0:
        logger.warning('Reached depth 10, not looking further.')
        return set()
    depth = depth-1
    deps = set()
    deps.add((module[0], module[1]))
    if not module[1] or module[1] == 'system':
        return deps # No version, it can only be a system library.
    depfile = os.path.join(os.environ['EPICS_MODULES_PATH'], module[0],
                           module[1], args.epicsbase, 'lib', args.targetarch,
                           '{}.dep'.format(module[0]))
    if not os.path.isfile(depfile):
        logger.warning('Could not find {}'.format(depfile))
        return deps

    with open(depfile) as depfilefh:
        for line in depfilefh:
            if line[0] == '#':
                continue
            depmodule = line.strip().split(',')
            if len(depmodule) == 2:
                rmodule = (
                    depmodule[0],
                    module_version(depmodule[0], depmodule[1], args.epicsbase, args.targetarch),
                    depmodule[1],
                )
            else:
                rmodule = (
                    depmodule[0],
                    module_version(depmodule[0], '', args.epicsbase, args.targetarch),
                    'auto',
                )
            deps |= recursive_solve(rmodule, args, depth)

    return deps


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Frontend to iocsh, rsyncs EEE modules')

    parser.add_argument('--prefix', metavar='DIR',
                        help='Installation prefix '
                        '(default {})'.format(os.environ['EPICS_MODULES_PATH']),
                        default='{}'.format(os.environ['EPICS_MODULES_PATH']))
    parser.add_argument('--base', metavar='EPICS-BASE', dest='epicsbase',
                        help='EPICS base version '
                        '(default {})'.format(os.environ['BASE']),
                        default='{}'.format(os.environ['BASE']))
    parser.add_argument('--arch', metavar='EPICS-TARGET-ARCH', dest='targetarch',
                        help='EPICS target architecture '
                        '(default {})'.format(os.environ['EPICS_HOST_ARCH']),
                        default='{}'.format(os.environ['EPICS_HOST_ARCH']))

    parser.add_argument('--user-dependency', action='append', default=[],
                        help='Add any user specified dependency <name>,<version>. '
                        'Can be system libraries. Overrides any detected depedency.')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--info', action='store_true')

    parser.add_argument('files', metavar='st.cmd', default=[],
                        nargs='*', help='Path to st.cmd')


    parser.add_argument('-r', metavar='module,version', dest='modules', action='append',
                        help='Load the specified module via \'require\'', nargs=1, default=[])
    parser.add_argument('-c', metavar='command', dest='commands', action='append',
                        help='Command is executed by the EPICS shell.', nargs=1, default=[])


    global args
    args, extras = parser.parse_known_args()

    for extra in extras:
        if extra.startswith('-3.'):
            args.epicsbase = extra[1:]

    ignored_extensions = [ 'db', 'dbt', 'template', 'subs', 'subst', 'dbd', 'so' ]

    files = []
    for st_cmd in args.files:
        if os.path.splitext(st_cmd)[1] not in ignored_extensions:
            files.append(st_cmd)

    for mod in args.modules:
        files.append(mod[0])

    commands = []
    for cmd in args.commands:
        commands.append(cmd[0])

    if args.debug:
        logging.getLogger(__name__).setLevel(logging.DEBUG)
    elif args.info:
        logging.getLogger(__name__).setLevel(logging.INFO)

    args.prefix = args.prefix.rstrip(os.path.sep)

    global rsync
    rsync = RSYNC(args.prefix, args.epicsbase, args.targetarch)
    dpres = DependencyResolver(files, prefix = args.prefix, eb_version = args.epicsbase, ta = args.targetarch,
                               ud = args.user_dependency, req_snippets = commands)




if __name__ == '__main__':
    logging.basicConfig(format='%(filename)s: %(message)s')
    main()
