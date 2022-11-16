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
rule interested
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
print(matches)