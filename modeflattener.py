from future.utils import viewitems, viewvalues
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.analysis.simplifier import *
from miasm.expression.expression import *
from miasm.core.asmblock import *
from miasm.arch.x86.arch import mn_x86
from miasm.core.utils import encode_hex

from argparse import ArgumentParser
import time
import logging
import pprint

from mod_utils import *

def setup_logger(loglevel):
    FORMAT = '[%(levelname)s] %(message)s'
    logging.basicConfig(format=FORMAT)
    logger = logging.getLogger('modeflattener')

    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)

    logger.setLevel(numeric_level)

    return logger

# https://synthesis.to/2021/03/15/control_flow_analysis.html
def calc_flattening_score(asm_graph):
    score = 0.0
    for head in asm_graph.heads_iter():
        dominator_tree = asm_graph.compute_dominator_tree(head)
        for block in asm_graph.blocks:
            block_key = asm_graph.loc_db.get_offset_location(block.lines[0].offset)
            dominated = set(
                [block_key] + [b for b in dominator_tree.walk_depth_first_forward(block_key)])
            if not any([b in dominated for b in asm_graph.predecessors(block_key)]):
                continue
            score = max(score, len(dominated)/len(asm_graph.nodes()))
    return score

# callback to stop disassembling when it encounters any jump
def stop_on_jmp(mdis, cur_bloc, offset_to_dis):
    jmp_instr_check = cur_bloc.lines[-1].name in ['JMP','JZ','JNZ']

    if jmp_instr_check:
        cur_bloc.bto.clear()
        offset_to_dis.clear()

def deflat(ad, func_info):
    main_asmcfg, main_ircfg = func_info

    # get flattening info
    relevant_blocks, dispatcher, pre_dispatcher = get_cff_info(main_asmcfg)
    dispatcher_blk = main_asmcfg.getby_offset(dispatcher)
    dispatcher_first_instr = dispatcher_blk.lines[0]
    state_var = dispatcher_first_instr.get_args_expr()[1]

    _log = logging.getLogger('modeflattener')
    _log.info('dispatcher: %#x' % dispatcher)
    _log.info('pre_dispatcher: %#x' % pre_dispatcher)
    _log.info('state_var: %s' % state_var)
    _log.info('relevant_blocks (%d) : '%len(relevant_blocks)
              + ', '.join([hex(addr) for addr in relevant_blocks]))
    print()

    backbone = {}
    fixed_cfg = {}
    val_list = []
    rel_blk_info = {}

    machine = Machine(cont.arch)

    for addr in relevant_blocks:
        _log.debug("Getting info for relevant block @ %#x"%addr)
        loc_db = LocationDB()
        mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
        mdis.dis_block_callback = stop_on_jmp
        asmcfg = mdis.dis_multiblock(addr)

        lifter = machine.lifter_model_call(loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
        ircfg_simplifier = IRCFGSimplifierCommon(lifter)
        ircfg_simplifier.simplify(ircfg, addr)
        #save_cfg(ircfg,'ir_%x'%addr)
    
        # marking the instructions affecting the state variable as nop_addrs
        nop_addrs = find_state_var_usedefs(ircfg, state_var)
        rel_blk_info[addr] = (asmcfg, nop_addrs)

        head = loc_db.get_offset_location(addr)
        ssa_simplifier = IRCFGSimplifierSSA(lifter)
        ssa = ssa_simplifier.ircfg_to_ssa(ircfg, head)
        #we only use do_propagate_expressions ssa simp pass
        ssa_simplifier.do_propagate_expressions(ssa, head)
        #save_cfg(ircfg, 'ssa_%x'%addr)

        # find the possible values of the state variable
        var_asg, tmpval_list = find_var_asg(ircfg, {state_var},loc_db,mdis)
        _log.debug('%#x %s' % (addr, var_asg))

        # adding all the possible values to a global list
        val_list += tmpval_list

        last_blk = list(asmcfg.blocks)[-1]
        # checking the type of relevant blocks on the basis of no. of possible values
        if len(var_asg) == 1:
            var_asg['next'] = hex(var_asg['next'])
            #map value of state variable in rel block
            fixed_cfg[hex(addr)] = var_asg
        elif len(var_asg) > 1:
            #extracting the condition from the last 3rd line
            cond_mnem = last_blk.lines[-3].name
            _log.debug('cond used: %s' % cond_mnem)
            if cond_mnem=='MOV':
                cond_mnem = last_blk.lines[-4].name
            var_asg['cond'] = cond_mnem
            var_asg['true_next'] = hex(var_asg['true_next'])
            var_asg['false_next'] = hex(var_asg['false_next'])
            # map the conditions and possible values dictionary to the cfg info
            fixed_cfg[hex(addr)] = var_asg
        elif len(last_blk.lines)==1 and len(var_asg)==0:
                #tail has a single instruction ie. jmp and no assignments
                tail = addr
                _log.debug("found backbone tail @ %#x" % addr)
        else:
            _log.error("no state variable assignments found for relevant block @ %#x" % addr)
            # return empty patches as deobfuscation failed!!
            return {}


    _log.debug('val_list: ' + ', '.join([hex(val) for val in val_list]))

    # get the value for reaching a particular relevant block
    for lbl, irblock in viewitems(main_ircfg.blocks):
        for assignblk in irblock:
            asg_items = assignblk.items()
            if asg_items:    # do not enter if nop
                dst, src = asg_items[0]
                if isinstance(src, ExprOp):
                    if src.op == 'FLAG_EQ_CMP':
                        arg = src.args[1]
                        if isinstance(arg, ExprInt):
                            if int(arg) in val_list:
                                cmp_val = int(arg)
                                var, locs = irblock[-1].items()[0]
                                true_dst = main_ircfg.loc_db.get_location_offset(locs.src1.loc_key)
                                backbone[hex(cmp_val)] = hex(true_dst)

    _log.debug('***** BACKBONE *****\n' + pprint.pformat(backbone))

    for offset, link in fixed_cfg.items():
        if 'cond' in link:
            tval = fixed_cfg[offset]['true_next']
            fval = fixed_cfg[offset]['false_next']
            fixed_cfg[offset]['true_next'] = backbone[tval]
            fixed_cfg[offset]['false_next'] = backbone[fval]
        elif 'next' in link:
            fixed_cfg[offset]['next'] = backbone[link['next']]
        else:
            # the tail doesn't has any condition
            tail = int(offset, 16)

    # unmark tail as a relevant block
    rel_blk_info.pop(tail)
    _log.debug('removed tail @ %#x from relevant_blocks' % tail)

    _log.debug('******FIXED CFG*******\n' + pprint.pformat(fixed_cfg))

    tail = main_asmcfg.getby_offset(tail).lines[-1]
    # get the backbone info from dispatcher and tail
    backbone_start, backbone_end = dispatcher, tail.offset + tail.l
    _log.debug('backbone_start = %#x, backbone_end = %#x' % (backbone_start, backbone_end))

    patches = {}

    for addr in rel_blk_info.keys():
        _log.info('=> cleaning relevant block @ %#x' % addr)
        asmcfg, nop_addrs = rel_blk_info[addr]
        link = fixed_cfg[hex(addr)]
        instrs = [instr for blk in asmcfg.blocks for instr in blk.lines]
        last_instr = instrs[-1]
        end_addr = last_instr.offset + last_instr.l
        # calculate original length of block before patching
        orig_len = end_addr - addr
        # nop the jmp to pre-dispatcher
        nop_addrs.add(last_instr.offset)
        _log.debug('nop_addrs: ' + ', '.join([hex(addr) for addr in nop_addrs]))
        patch = patch_gen(instrs, asmcfg.loc_db, nop_addrs, link)
        patch = patch.ljust(orig_len, b"\x90")
        patches[addr] = patch
        _log.debug('patch generated %s\n' % encode_hex(patch))

    _log.info(">>> NOPing Backbone (%#x - %#x) <<<" % (backbone_start, backbone_end))
    nop_len = backbone_end - backbone_start
    patches[backbone_start] = b"\x90" * nop_len

    return patches



if __name__ == '__main__':
    parser = ArgumentParser("modeflattener")
    parser.add_argument('filename', help="file to deobfuscate")
    parser.add_argument('patch_filename', help="deobfuscated file name")
    parser.add_argument('address', help="obfuscated function address")
    parser.add_argument('-b',"--baseaddr", help="file base address")
    parser.add_argument('-a', "--all", action="store_true",
                        help="find and deobfuscate all flattened functions recursively")
    parser.add_argument('-l', "--log", help="logging level (default=INFO)",
                        default='info')

    args = parser.parse_args()

    loglevel = args.log
    _log = setup_logger(loglevel)

    deobf_start_time = time.time()

    forg = open(args.filename, 'rb')
    fpatch = open(args.patch_filename, 'wb')
    fpatch.write(forg.read())

    loc_db = LocationDB()

    global cont
    cont = Container.from_stream(open(args.filename, 'rb'), loc_db)

    supported_arch = ['x86_32', 'x86_64']
    _log.info("Architecture : %s"  % cont.arch)

    if cont.arch not in supported_arch:
        _log.error("Architecture unsupported : %s" % cont.arch)
        exit(1)
    try:
        if args.baseaddr:
            _log.info('Base Address:'+args.baseaddr)
            baseaddr=int(args.baseaddr,16)
        elif cont.executable.isPE():
            baseaddr=0x400C00
            _log.info('Base Address:%x'%baseaddr)
    except AttributeError:
        section_ep = cont.bin_stream.bin.virt.parent.getsectionbyvad(cont.entry_point).sh
        baseaddr = section_ep.addr - section_ep.offset
        _log.info('Base Address:%x'%baseaddr)

    machine = Machine(cont.arch)
    mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)

    ad = int(args.address, 0)
    todo = [(mdis, None, ad)]
    done = set()
    all_funcs = set()
    all_funcs_blocks = {}

    while todo:
        mdis, caller, ad = todo.pop(0)
        if ad in done:
            continue
        done.add(ad)
        asmcfg = mdis.dis_multiblock(ad)
        lifter = machine.lifter_model_call(mdis.loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

        _log.info('found func @ %#x (%d)' % (ad, len(all_funcs)))

        all_funcs.add(ad)
        all_funcs_blocks[ad] = (asmcfg, ircfg)

        if args.all:
            for block in asmcfg.blocks:
                instr = block.get_subcall_instr()
                if not instr:
                    continue
                for dest in instr.getdstflow(mdis.loc_db):
                    if not dest.is_loc():
                        continue
                    offset = mdis.loc_db.get_location_offset(dest.loc_key)
                    todo.append((mdis, instr, offset))

    for ad in all_funcs:
        asmcfg = all_funcs_blocks[ad][0]
        score = calc_flattening_score(asmcfg)
        if score > 0.9:
            print('-------------------------')
            print('|    func : %#x    |' % ad)
            print('-------------------------')
            fcn_start_time = time.time()
            patches = deflat(ad, all_funcs_blocks[ad])

            if patches:
                for offset, data in patches.items():
                    fpatch.seek(offset - baseaddr)
                    fpatch.write(data)

                fcn_end_time = time.time() - fcn_start_time
                _log.info("PATCHING SUCCESSFUL for function @ %#x (%.2f secs)\n" % (ad, fcn_end_time))
            else:
                _log.error("PATCHING UNSUCCESSFUL for function @ %#x\n" % ad)

        else:
            _log.error("unable to deobfuscate func %#x (cff score = %f)\n" % (ad, score))

    fpatch.close()
    deobf_end_time = time.time() - deobf_start_time

    _log.info("Deobfuscated file saved at '%s' (Total Time Taken : %.2f secs)" % (args.patch_filename, deobf_end_time))
