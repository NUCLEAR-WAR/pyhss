import copy

def select_scope(definition,set_id,impi):
 aliases=definition.get('digest_identity_aliases') or {}
 canonical=aliases.get(impi,impi)
 return [p['identity'] for p in definition['public_identities'] if p['set_id']==set_id and canonical in [aliases.get(x,x) for x in p['private_identities']]]

def test_two_impis_one_irs():
 d={'private_identities':['a@x','b@x'],'public_identities':[{'identity':'sip:a@x','set_id':'s','private_identities':['a@x','b@x']},{'identity':'sip:b@x','set_id':'s','private_identities':['b@x']}]}
 assert select_scope(d,'s','a@x')==['sip:a@x']
 assert select_scope(d,'s','b@x')==['sip:a@x','sip:b@x']
def test_independent_irs():
 d={'public_identities':[{'identity':'sip:a@x','set_id':'s1','private_identities':['a@x']},{'identity':'sip:b@x','set_id':'s2','private_identities':['a@x']}]}
 before=copy.deepcopy(d)
 assert select_scope(d,'s1','a@x')==['sip:a@x']
 assert d==before
