# pip install yara-python
import yara

# testrule = """
# rule coinminer
# {
#     meta:
#         description = "This is just an example,coinminer config extra"
#     strings:
#         $start = {0A 7B 0A 20 20 20 20 22 61 70 69 }
#         $end = {20 66 61 6C 73 65 0A 7D 0A}
#     condition:
#         $start and $end
# }
# """

testrule = """
rule interested : tag1
{
    meta:
        description = "This is just an example,coinminer config extra"
    strings:
        $hello = "interested" nocase 
    condition:
        $hello
}
"""

rule = yara.compile(source=testrule)
filecontent = open("/workspaces/helloworld/README.md", "rb").read()
matches = rule.match(data=filecontent)
# print(type(matches))
# print(matches[0])
# print(type(matches[0]))
print(matches[0].meta)
print(matches[0].namespace)
print(matches[0].rule)
print(matches[0].strings)
print(matches[0].tags)




