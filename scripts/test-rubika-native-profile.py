import importlib.util,struct,tempfile,unittest
from pathlib import Path
s=importlib.util.spec_from_file_location('native',Path(__file__).with_name('inspect-rubika-native-profile.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

def fixture():
    names=sorted(m.NAMES);strings=bytearray(b'\0');text=bytearray();entries=[]
    for name in names:
        at=len(strings);strings.extend(name.encode()+b'\0');start=len(text)
        code=b'\xb8\x5c\0\0\0\xc3'if 'GetConnectionMaxLayer'in name else b'\xc7\x44\x24\x01\x36\x2e\x30\x2e\x66\xc7\x44\x24\x05\x30\x00\xc3'
        text.extend(code);entries.append(struct.pack('<IBBHQQ',at,0x12,0,1,0x1000+start,len(code)))
    data=bytearray(64+4*64);data[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<HHI',data,16,3,62,1);struct.pack_into('<Q',data,40,64);struct.pack_into('<HH',data,58,64,4)
    text_at=len(data);data.extend(text);str_at=len(data);data.extend(strings);sym_at=len(data);data.extend(b''.join(entries))
    sections=[(0,)*10,(0,1,6,0x1000,text_at,len(text),0,0,1,0),(0,3,0,0,str_at,len(strings),0,0,1,0),(0,11,0,0,sym_at,len(entries)*24,2,0,8,24)]
    for i,section in enumerate(sections):struct.pack_into('<IIQQQQIIQQ',data,64+i*64,*section)
    return data,sections

class NativeTests(unittest.TestCase):
    def test_bounded_symbols_and_immediate_return(self):
        data,_=fixture();result=m.observations(data);self.assertEqual(len(result['functions']),6)
        self.assertEqual([r['immediateReturn']for r in result['functions']if'immediateReturn'in r],[92]*3)
        self.assertTrue(next(r for r in result['functions']if'legacyVersionLiteralPresent'in r)['legacyVersionLiteralPresent'])
        self.assertFalse(result['installedOrExecuted']);self.assertFalse(result['binaryEquivalentToUpstreamProven'])
    def test_wrong_architecture_and_header(self):
        for at,value in [(0,0),(4,1),(5,2),(18,3),(58,0),(60,0)]:
            data,_=fixture();data[at]=value
            with self.assertRaises(ValueError):m.elf_symbols(data)
    def test_truncated_section_table(self):
        data,_=fixture()
        for length in [0,63,64,319]:
            with self.assertRaises(ValueError):m.elf_symbols(data[:length])
    def test_bad_symbol_offsets_names_and_size(self):
        for offset,value in [(0,0xffffffff),(6,10),(8,0xffffffff),(16,4097)]:
            data,ss=fixture();at=ss[3][4]
            struct.pack_into('<H'if offset==6 else '<Q'if offset in [8,16]else '<I',data,at+offset,value)
            with self.assertRaises(ValueError):m.elf_symbols(data)
    def test_unknown_instruction_is_not_a_layer_value(self):
        data,ss=fixture();index=next(i for i,name in enumerate(sorted(m.NAMES))if'GetConnectionMaxLayer'in name)
        address=struct.unpack_from('<Q',data,ss[3][4]+index*24+8)[0];data[ss[1][4]+address-0x1000]=0x90
        with self.assertRaises(ValueError):m.observations(data)
    def test_missing_or_duplicate_symbol(self):
        data,ss=fixture();struct.pack_into('<I',data,ss[3][4],0)
        with self.assertRaises(ValueError):m.observations(data)
        data,ss=fixture();data[ss[3][4]+24:ss[3][4]+48]=data[ss[3][4]:ss[3][4]+24]
        with self.assertRaises(ValueError):m.elf_symbols(data)
    def test_unterminated_symbol_names(self):
        data,ss=fixture();data[ss[2][4]:ss[2][4]+ss[2][5]]=b'x'*ss[2][5]
        with self.assertRaises(ValueError):m.elf_symbols(data)
    def test_apk_hash_gate(self):
        with tempfile.TemporaryDirectory()as directory:
            p=Path(directory)/'fixture.apk';p.write_bytes(b'not the official APK')
            with self.assertRaisesRegex(ValueError,'SHA'):m.inspect(p)

if __name__=='__main__':unittest.main()
