"""Synthetic malformed-input and instruction-boundary tests, no APK execution."""
import importlib.util, struct, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('references',Path(__file__).with_name('inspect-dex-call-references.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def header():
    data=bytearray(112);data[:8]=b'dex\n039\0'
    struct.pack_into('<III',data,32,len(data),112,0x12345678)
    return data

class ReferencesTests(unittest.TestCase):
    def test_leb_bounds(self):
        self.assertEqual(m.leb(b'\xff\xff\xff\xff\x0f',0),(0xffffffff,5))
        for value in [b'',b'\x80',b'\xff'*5,b'\xff\xff\xff\xff\x10']:
            with self.assertRaises(ValueError):m.leb(value,0)
    def test_header_and_table_bounds(self):
        dex=m.Dex(header());self.assertEqual(dex.selected(['Lfixture;']),[])
        for at,value in [(32,111),(36,120),(40,0),(56,500001),(56,1)]:
            data=header();struct.pack_into('<I',data,at,value)
            with self.assertRaises(ValueError):m.Dex(data)
        data=header();data[:8]=b'dex\n041\0'
        with self.assertRaises(ValueError):m.Dex(data)
    def test_instruction_widths(self):
        for words,width in [([0],1),([0x1a,0],2),([0x1b,0,0],3),([0x18,0,0,0,0],5),([0xfa,0,0,0],4)]:
            self.assertEqual(m.instruction_width(words,0),width)
        for words in [[0x1b,0],[0xfa,0,0],[0xe3]]:
            with self.assertRaises(ValueError):m.instruction_width(words,0)
    def test_payload_alignment_and_lengths(self):
        for words in [[0x100,1,0,0,0,0],[0x200,1,0,0,0,0],[0x300,1,1,0,42]]:
            self.assertEqual(m.instruction_width(words,0),len(words))
        for words,offset in [([0,0x100,0,0,0],1),([0x100,1],0),([0x300,3,1,0,0,0],0),([0x400,0],0)]:
            with self.assertRaises(ValueError):m.instruction_width(words,offset)
    def test_string_reference_and_signed_literal(self):
        data=header();data.extend(b'\0'*4);struct.pack_into('<II',data,56,1,112)
        struct.pack_into('<I',data,112,len(data));data.extend(b'\x04call\0')
        while len(data)%4:data.append(0)
        offset=len(data);data.extend(struct.pack('<HHHHII',1,0,0,0,0,5))
        data.extend(struct.pack('<5H',0x001a,0,0xf012,0x000e,0))
        struct.pack_into('<I',data,32,len(data));dex=m.Dex(data)
        result=dex.code(offset)
        self.assertEqual(result['references'],[{'offset':0,'kind':'string','register':0,'value':'call'},{'offset':2,'kind':'literal','register':0,'value':-1}])
        with self.assertRaises(ValueError):dex.string(1)
        with self.assertRaises(ValueError):dex.code(offset+1)
    def test_code_bounds(self):
        data=header();data.extend(struct.pack('<HHHHII',1,0,0,0,0,65537));struct.pack_into('<I',data,32,len(data))
        with self.assertRaises(ValueError):m.Dex(data).code(112)
    def test_invoke_width_and_register_bounds(self):
        def code(words):
            data=header();data.extend(struct.pack('<HHHHII',2,0,0,0,0,len(words)))
            data.extend(struct.pack('<'+'H'*len(words),*words));struct.pack_into('<I',data,32,len(data))
            dex=m.Dex(data)
            dex.method=lambda index:{'owner':'Lfixture;','name':'method'+str(index),'prototype':'()V'}
            return dex.code(112)
        result=code([0x206e,7,0x10,0x0e])
        self.assertEqual(result['references'][0]['registers'],[0,1])
        self.assertEqual(result['references'][0]['name'],'method7')
        result=code([0x0274,8,0,0x0e])
        self.assertEqual(result['references'][0]['registers'],[0,1])
        for words in [[0x606e,0,0],[0x106e,0,2],[0x0274,0,1],[0x206e,0]]:
            with self.assertRaises(ValueError):code(words)
    def test_explicit_prefix_required_before_file_read(self):
        for prefixes in [[],[''],['../../anything'],['Lx;']*17]:
            with self.assertRaises(ValueError):m.inspect(Path('nonexistent.apk'),prefixes)

if __name__=='__main__':unittest.main()
