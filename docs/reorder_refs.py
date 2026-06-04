import re

filepath = r"c:\local_store\files\my_workspace\acas\docs\Disertatie_Matei_Rares_draft4.md"
with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

bib_marker = "\nBibliografie\n"
bib_start_idx = content.find(bib_marker)
anexe_idx = content.find("\nAnexe\n", bib_start_idx)

text_before_bib = content[:bib_start_idx]
bib_section = content[bib_start_idx:anexe_idx]
rest_after_bib = content[anexe_idx:]

order = []
for m in re.finditer(r"\[(\d+)\]", text_before_bib):
    num = int(m.group(1))
    if num not in order:
        order.append(num)

mapping = {old: new + 1 for new, old in enumerate(order)}

def apply_mapping(text, mapping):
    def replace(m):
        num = int(m.group(1))
        if num in mapping:
            return "XREFX{}XREFX".format(mapping[num])
        return m.group(0)
    result = re.sub(r"\[(\d+)\]", replace, text)
    result = re.sub(r"XREFX(\d+)XREFX", lambda m: "[{}]".format(m.group(1)), result)
    return result

new_text_before_bib = apply_mapping(text_before_bib, mapping)

bib_content = bib_section[len(bib_marker):]
lines = bib_content.split("\n")
current_num = None
current_lines = []
raw_entries = {}

for line in lines:
    m = re.match(r"^\[(\d+)\](.*)$", line)
    if m:
        if current_num is not None:
            raw_entries[current_num] = "\n".join(current_lines).rstrip("\n")
        current_num = int(m.group(1))
        current_lines = [line]
    else:
        if current_num is not None:
            current_lines.append(line)

if current_num is not None:
    raw_entries[current_num] = "\n".join(current_lines).rstrip("\n")

preamble_lines = []
for line in lines:
    if re.match(r"^\[(\d+)\]", line):
        break
    preamble_lines.append(line)
preamble = "\n".join(preamble_lines)

print("Found {} bibliography entries: {}".format(len(raw_entries), sorted(raw_entries.keys())))

new_bib_entries = []
for old_num, new_num in sorted(mapping.items(), key=lambda x: x[1]):
    if old_num in raw_entries:
        old_entry_text = raw_entries[old_num]
        new_entry_text = re.sub(r"^\[" + str(old_num) + r"\]", "[{}]".format(new_num), old_entry_text)
        new_bib_entries.append((new_num, new_entry_text))

trailer = bib_content
for num in sorted(raw_entries.keys()):
    trailer = trailer.replace(raw_entries[num], "", 1)
trailer = trailer.strip()
if trailer:
    print("Trailer: {}".format(repr(trailer[:300])))

new_bib_entries_sorted = sorted(new_bib_entries, key=lambda x: x[0])
new_bib_content = preamble
for new_num, entry_text in new_bib_entries_sorted:
    new_bib_content += "\n" + entry_text + "\n"

if trailer:
    new_bib_content += "\n" + trailer + "\n"

new_bib_section = bib_marker + new_bib_content
new_content = new_text_before_bib + new_bib_section + rest_after_bib

with open(filepath, "w", encoding="utf-8") as f:
    f.write(new_content)

print("Done!")
print("Processed {} unique text citations, {} bib entries.".format(len(order), len(raw_entries)))
