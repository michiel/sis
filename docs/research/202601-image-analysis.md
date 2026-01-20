Image-Based PDF Exploits and the Case for an Image Analysis Crate
Historical Use of Images for PDF Exploitation
PDF documents have long been a target for attackers, and image data within PDFs is no exception. Embedded images in PDFs have historically been used to deliver exploits and hidden payloads. As far back as 2009, attackers exploited a buffer overflow in Adobe Reader’s JBIG2 image decoder to achieve remote code execution. A crafted PDF with a malicious JBIG2 image stream was used in the wild (Trojan.Pidief.E) to compromise systems
. This vulnerability (CVE-2009-0658) allowed an attacker to overflow memory via an embedded JBIG2 image, illustrating how image streams can conceal critical payloads. Throughout the 2010s, multiple image formats in PDFs were found vulnerable. JPEG2000 (JPX) images, TIFF images (often via the XFA forms feature), and other image filters saw numerous CVEs. For example, a 2018 exploit (CVE-2018-4990) leveraged an out-of-bounds memory flaw in Acrobat’s JPEG2000 decoder (JP2KLib). The attacker embedded a malformed JPEG2000 image in a PDF form field, combined with JavaScript that orchestrated a heap spray, resulting in arbitrary memory free and code execution
. This shows the common pattern of pairing an image exploit with JavaScript: the image corrupts memory, and script code then exploits that corruption to execute shellcode. In other cases, image data itself carried the entire exploit – e.g. malicious TIFF images were embedded in PDFs to exploit Adobe Reader (as in CVE-2010-0188)
. Attackers also used images for obfuscation of malicious code. A notable technique discovered in 2013 involved hiding JavaScript exploit code inside an image stream using steganography. The PDF’s JavaScript would extract and execute code hidden in an image XObject. In one case, malicious JS was encoded into a JPEG image stream (“icon” object) and read via PDF JS APIs (this.getIcon() and util.iconStreamFromIcon()), then eval’d at runtime
. This dual-layer obfuscation allowed the PDF to bypass antivirus detection, since the JavaScript was not visible in clear form – it was concealed in what appeared to be a normal image
. Although this is an advanced steganographic payload technique (malicious code embedded within image pixels), it demonstrates the lengths attackers went to weaponize images in PDFs beyond simple social engineering. In summary, images in PDFs have been used both as direct exploit vectors and as containers to hide malicious content. Early on, JBIG2 streams were used for straightforward memory corruption exploits
. Over time, attackers expanded to other image codecs (JPEG2000, TIFF, etc.), often in combination with scripting, to achieve reliable exploitation
. Additionally, images served as a medium to mislead analysts and automated scanners, by hiding exploit code in image data or by using uncommon image filters that scanners didn’t handle
. This historical trend underscores that image data is an important part of the PDF attack surface, not to be overlooked.
The Evolving Trend up to Today (and Beyond)
Over the last decade, PDF image exploits have continued to appear, though the focus has shifted as mitigations improved. In the early 2010s, many PDF exploits abused JavaScript or interactive features; however, as those vectors were hardened, attackers increasingly targeted lower-level components like font and image renderers. A 2017 BlackHat research study by Tencent’s Xuanwu Lab revealed how fertile this area is: by systematically fuzzing PDF readers’ image/font parsing, they discovered nearly 150 vulnerabilities in popular PDF viewers (Adobe Acrobat, Foxit, Chrome PDFium, etc.) in one year
. These included numerous bugs in image handling libraries – e.g. in PNG, JPEG2000, JBIG2, TIFF decoders – emphasizing that images remained a rich source of flaws. In recent years, high-profile exploits have proven that image-based PDF attacks are still very much alive. A striking example is the 2021 “FORCEDENTRY” iMessage exploit (attributed to NSO Group/Pegasus spyware), which utilized a PDF encapsulated in an image to perform a zero-click compromise on iPhones. The exploit leveraged an integer overflow in the JBIG2 decoder within Apple’s CoreGraphics PDF parsing library (CVE-2021-30860). By sending what looked like a GIF image via iMessage, the attackers triggered the JBIG2 vulnerability in the PDF parser and effectively built a Turing-complete virtual machine out of malicious JBIG2 segments
. This allowed arbitrary code execution without any user click. Google’s Project Zero called it “one of the most technically sophisticated exploits we’ve ever seen,” noting that the attackers implemented a CPU architecture in a JBIG2 image stream – a testament to how far image-based exploitation can be pushed
. In essence, an “obsolete” image format became the vehicle for a state-of-the-art attack in 2021. Today, most major PDF readers have patched the known holes (JBIG2, JPEG2000, etc.) and introduced sandboxing. Yet, the trend indicates that image parsing remains a critical weakness due to the complexity of codecs and the legacy code involved. Attackers will likely continue to search for obscure or under-maintained image format implementations in PDF ecosystems. We have to consider future formats as well – for instance, if PDF were to support newer image types (e.g. JPEG XL or HEIC in attachments or via rendering libraries), those would present new attack avenues. Moreover, attackers are expected to keep innovating in obfuscation, possibly using images in tandem with encryption or machine-learning-resistant patterns to hide malware. For example, we may see more steganography in images to smuggle payloads, knowing that deep image inspection is computationally expensive for defenders. In summary, as of today images still represent a serious attack surface in PDFs, as evidenced by recent exploits like the NSO JBIG2 attack
. Looking beyond today, any new image-handling features or image codecs used by PDF readers could introduce fresh vulnerabilities if not carefully audited. The arms race will continue: defenders need better automated analysis of image content, while attackers will find more novel ways (like multi-layered image obfuscation or leveraging rarely-used image subformats) to evade detection. This underscores the importance of fortifying our PDF analysis tool (sis-pdf) with robust image scanning capabilities.
Attack Surface of PDF Images Across Different Readers
From a security perspective, every image format that a PDF can embed becomes part of the reader’s attack surface. The PDF specification supports several image filters and formats, each handled by different codec libraries under the hood:
JPEG (DCTDecode) – Standard JPEG images (often used for color photographs in PDFs). Decoded by JPEG libraries (e.g. libjpeg or similar in readers).
JPEG2000 (JPXDecode) – Wavelet-based images for high-quality compression. Many readers use OpenJPEG or custom JPEG2000 engines (e.g. Adobe’s JP2KLib.dll) to decode these
. This format is complex, and multiple memory corruption bugs have been found in its parsers
.
JBIG2 (JBIG2Decode) – Monochrome image compression specialized for binary images (often scanned text). Decoding is often based on the open-source Xpdf’s jbig2 code or derivatives
. JBIG2’s complexity (with its segment processing and pattern-matching logic) has led to severe vulnerabilities
.
TIFF/CCITT (CCITTFaxDecode) – Fax compression (Group 3/4) for bilevel images, and more generally, some PDF workflows (especially XFA forms) can embed TIFF images. PDF viewers might use libtiff for these
, which has had exploitable bugs (e.g. an out-of-bounds write in the PixarLogDecode compressor, CVE-2016-5875
).
PNG, BMP, GIF – While not native PDF image filters, these can appear in certain contexts. Notably, Adobe’s XFA (XML Forms Architecture) allows embedding images in formats like PNG, TIFF, GIF inside form content or as resources
. For example, Acrobat’s XFA module uses libpng and libtiff for image handling
. If those libraries have flaws, an attacker-crafted XFA form image can be malicious (indeed, the CVE-2010-0188 TIFF exploit was in an XFA stream
).
Raw/Other – PDFs can use general compression filters (Flate, LZW, RunLength, etc.) on image data. They could, for instance, Flate-compress a BMP or raw bitmap. Attackers have abused this flexibility: e.g., using Flate + JBIG2 filters on a non-image payload to confuse scanners
.
Different PDF readers expose different subsets of this attack surface depending on which libraries they include and what features they enable. Adobe Acrobat/Reader historically included all the above (JP2K, JBIG2, etc.), making it fully feature-rich but also widely exposed. Other viewers vary:
Chrome PDFium uses open-source decoders (OpenJPEG, libtiff, etc.), inheriting their vulnerabilities. For instance, the libtiff bug CVE-2016-5875 affected Chrome’s PDF viewer until patched
. Chrome at one point even enabled XFA (which brought in libpng/libtiff) and later disabled it due to security concerns
.
Foxit Reader supports JBIG2, JPEG2000, etc., and was also affected by the libtiff issue
.
Apple Preview (macOS) and iOS rely on Apple’s CoreGraphics and ImageIO frameworks. As seen with the NSO exploit, even when high-level scripting is absent, the built-in image codecs (like Apple’s JBIG2 code, derived from Xpdf) can be targeted
.
Smaller or hardened viewers (e.g. mupdf-based tools) might omit some formats. For example, some lightweight PDF readers do not implement JPEG2000 or JBIG2 to reduce code size (or only implement them partially). This can reduce their attack surface – a malicious PDF using JBIG2 might not even render in such a viewer (though the user may then open it in a more capable reader, so it’s not a true security solution).
The attack surface spans not only the image decoder libraries but the surrounding logic in the PDF parser. An image embedded in a PDF goes through multiple layers: the PDF’s own parsing of object dictionaries (dimensions, color space, etc.), the filter decompression, and then the image codec. Each layer can have vulnerabilities. For instance, a bug might exist in how a PDF reader allocates buffers for a huge image size (e.g. a size calculation overflow before even sending data to the decoder). Many CVEs involve integer overflow or mishandling of image dimensions and indexing. One example is the Adobe JPEG2000 memory corruption CVE-2017-3044, which was related to image scaling – likely an issue in how image dimensions were handled in memory
. Moreover, different readers use different mitigation strategies. Modern Acrobat and Chrome run image decoding in sandboxed processes, limiting impact, whereas some other readers might not. But even with sandboxing, a critical image exploit can often escape the sandbox or be combined with logic to achieve more damage, especially if the image decoding process has system access (consider that some readers might not sandbox the image parsing thread). In summary, any image format that a PDF supports is an attack vector, and the risk is amplified by the diversity of third-party image libraries in use. Attackers can craft one malicious image and potentially exploit multiple readers if they share the vulnerable library. A case in point: the aforementioned libtiff PixarLog bug (CVE-2016-5875) was found to impact Acrobat (via its plugin), Chrome (when XFA was enabled), and Foxit – all through the same root cause
. This cross-platform exposure is why images in PDFs are so potent for attackers.
Notable Vulnerabilities and Exploitation Techniques in PDF Images
JBIG2 exploits: JBIG2 has been one of the most notorious image attack vectors. Beyond the 2009 exploit
, researchers and attackers demonstrated that JBIG2’s design (segments that can refer to each other, define symbol dictionaries, etc.) can be abused to perform arbitrary operations in memory. The NSO “FORCEDENTRY” exploit is essentially a series of malicious JBIG2 segments that cause an integer overflow and then write out of bounds to craft a fake object in memory
. By manipulating JBIG2’s segment references and lengths, the exploit “unbounded” the image drawing buffer and wrote data to an adjacent object’s fields, eventually leading to control of program flow
. This was possible because the JBIG2 decoder did not properly check segment references and buffer sizes – a parser logic flaw leading to a heap overflow. JBIG2 streams have also been used more stealthily: the Avast Virus Lab noted a trick where attackers used JBIG2Decode on non-image data. They effectively encoded a malicious payload (a TIFF exploit) as if it were a monochrome image: setting the image to 1 pixel tall and a very wide width, so the bytes decode in one long strip
. This allowed the malicious content to be hidden behind a JBIG2 filter (which many AV engines at the time did not decode)
. In their case, the hidden content was actually another exploit (CVE-2010-0188 TIFF), showing how JBIG2 can serve as a container for multi-stage attacks. JPEG2000 vulnerabilities: JPEG2000’s codebase (both open-source OpenJPEG and Adobe’s implementation) has yielded many CVEs. These include out-of-bounds reads/writes, use-after-frees, and integer overflows. For instance, CVE-2018-4990 mentioned earlier was an arbitrary free triggered by a JPEG2000 image – the image’s malformed structure led Acrobat’s JP2KLib to free a pointer it shouldn’t, which the attacker then exploited with a heap spray
. Another example, CVE-2017-3044, was a memory corruption due to how the JPEG2000 engine handled color palette information, leading to code execution
. Generally, JPEG2000 files are complex (with nested “box” structures, tiling, multiple color components) and the parsing code is error-prone. Malicious JPX streams might, for instance, claim to have an enormous image size or contain inconsistent metadata that causes buffer miscalculations. If a PDF contains such a JPX stream, a vulnerable reader could overflow a heap buffer when decoding or even just when measuring the image for display. TIFF/PNG and others: In the context of PDF, TIFF images often appear in XFA forms or as embedded files. One famous bug, CVE-2010-0188, was a TIFF image buffer overflow in Adobe Reader’s TIFF parsing – this was widely exploited in malicious PDFs around 2010. Attackers hid the TIFF inside the PDF’s XFA section (encoded as base64 within an XML stream), which was then automatically parsed by Reader’s form engine, leading to code execution
. Similarly, PNG vulnerabilities (like overflow in libpng’s ancillary chunk handling) could be triggered if a PDF somehow embedded a PNG (Acrobat’s XFA uses libpng, so a crafted XFA image could hit such a bug
). GIF and BMP are less commonly used in PDFs, but if a reader supports converting them (e.g. Acrobat’s conversion plugin), an exploit could target that (e.g. a BMP with a malformed header causing a heap overflow in the conversion process). Combined techniques: Attackers often chain multiple PDF features to achieve their goal. An image exploit alone might corrupt memory, but to reliably run shellcode, the exploit may use JavaScript or form actions for heap manipulation. We saw this in CVE-2018-4990: the JPEG2000 flaw allowed an arbitrary free, but the attacker’s JavaScript then reallocated that memory with controlled data (heap spray) and achieved code execution
. Another combined technique is steganography with JavaScript extraction (EdgeSpot’s 2019 finding): the malicious PDF used two layers of obfuscation – first, a deceptive method to read hidden content (getPageNthWord trick), second, actual steganographic hiding of JS in an image stream
. The JavaScript code in the PDF read the image’s bytes and decoded the hidden message to execute it
. This is a reminder that not all “image-based” threats are memory exploits; some are about using images to hide code or data. Denial-of-service (DoS) vectors: Apart from code execution, images can be used to cause crashes or resource exhaustion. A trivial example is a decompression bomb – e.g., a CCITTFaxDecode image that expands to an extremely large bitmap (say a 100,000 x 100,000 monochrome image). This could freeze or crash a reader due to memory exhaustion. Similarly, a malformed image could trigger endless loops in a poorly implemented decoder (locking up the application). While these DoS issues are less severe than RCE, they are still part of the attack surface (especially for causing disruptions or as part of a multi-stage exploit where a crash bypasses some protection). In summary, the parser vulnerabilities in PDF image handling range from memory corruptions (buffer overflows, UAFs, integer overflows) in codecs like JBIG2, JPEG2000, TIFF, to logic bugs that allow sneaky usage of image filters for unintended data (e.g. using JBIG2 on non-image data
). Many of these vulnerabilities are exploitable for code execution – often requiring pairing with scripting or ROP techniques – and have been actively used in malware campaigns. The presence of such vulnerabilities is well-documented by CVEs and security research over the years, and new instances continue to emerge as attackers probe the complex image parsing code in PDF readers.
Detecting Malicious Image Usage: Strategies and Heuristics
Detecting image-based exploits in PDFs is challenging, but we can outline both static heuristics (rules that analyze the PDF structure and image bytes without executing them) and dynamic checks (actual parsing or emulation of the image content) to catch suspicious indicators.
Static Analysis Heuristics
In a static scan, we inspect the PDF’s objects and streams for telltale signs of malicious image content. Key heuristics include:
Presence of risky image filters: Simply flagging the use of certain image compression filters can raise an alert. For instance, any PDF object using /Filter /JBIG2Decode is worth scrutiny
, because JBIG2 is rarely used except in scanned documents and has a history of exploits. Likewise, /JPXDecode (JPEG2000) should be noted – many benign PDFs won’t use JPEG2000, so its presence is a hint of either advanced features or potentially an exploit attempt. These indicators aren’t proof of maliciousness by themselves, but they narrow the scope for deeper analysis.
Multiple or nested filters on one stream: If an image stream has an unusual filter chain (e.g. FlateDecode then JBIG2Decode, or multiple layers of image filters), it’s suspect. The PDF spec allows multiple filters on a stream, but attackers abuse this to hide content. The Avast example showed JBIG2Decode used after FlateDecode on what turned out to be non-image data
. A static rule could be: if an Image XObject uses JBIG2Decode and the data was further compressed (Flate/etc.), flag it. Legitimate uses of double-compression on images are rare.
Anomalous image dimensions or parameters: Extremely large dimensions or weird aspect ratios can indicate trouble. For example, a JBIG2 image that claims to be 1 pixel high and tens of thousands of pixels wide (or vice versa) is likely a trick to encode data linearly
. Similarly, if a color image claims an absurd number of color components or bits per component (outside typical ranges), or if a CCITT Fax image dictionary has unusual /K or /Columns values, these could be malformations intended to confuse parsers. Static analysis can check the image dictionary: if width*height is excessively large (beyond some threshold), raise a warning (image.extreme_dimensions).
Suspicious global data in JBIG2: JBIG2 streams can have a /JBIG2Globals segment (shared symbols). If a PDF contains a JBIG2Globals object with a very large stream or weird content, that’s a red flag – exploits might stash code or large lookup tables in global segments. A heuristic could be: if JBIG2Globals present and its size >> typical (e.g. >1MB), flag it, as most scanned-doc JBIG2 streams wouldn’t have such large global data.
Correlations with JavaScript or interactive content: As noted, image exploits often pair with JavaScript. A static analysis can’t execute the JS, but it can detect if the PDF has both an image filter like JBIG2/JPX and an embedded script. If a single PDF contains, say, a JBIG2 stream and a /Names entry for JavaScript (or an OpenAction launching JS), that combination is highly suspicious. This heuristic relies on cross-object analysis: we’d mark a finding if “exploit-prone image present and script present”. In our SonicWall example, the PDF had a JPEG2000 payload and a Launch action script to trigger it
.
Known bad patterns in image bytes: We can perform lightweight scans of the raw image stream bytes for signatures. For instance, look for the byte sequences of file headers embedded in images. The Avast case was detectable by noticing a TIFF header (II* or MM*) present in the Flate-decoded data before JBIG2 decoding
. Another example: if an image’s bytes contain strings like “JS” or segments of JavaScript code (in the steganography case
, the hidden JS might have identifiable keywords once decoded). We could attempt to partially decompress image streams (e.g. apply Flate but not JBIG2) to see if any ASCII text or known exploit shellcode patterns emerge. This must be done carefully (to avoid false positives), but it’s a possible static heuristic.
Unusual image object context: Check where the image is used. If the image XObject is referenced in a form field’s icon or an annotation’s appearance XObject, and especially if an action or JavaScript is triggered by that field, it could be malicious. For example, an embedded image in a button (as icon) that is referenced by a mouseover JS event is suspicious (this was the case with the CVE-2018-4990 PDF: image in a form button “Button1” with JS that triggers it
). Static analysis can’t fully tie the runtime behavior, but noticing an image is inside an AcroForm object or annotation that has an /AA (additional action) entry can prompt deeper analysis.
It’s important to balance these heuristics to avoid too many false alarms. Many scanned PDFs legitimately use JBIG2 or CCITT (especially corporate documents, fax archives, etc.), so presence of those filters alone might be a low-severity finding (informational). The heuristics become higher confidence when multiple factors combine – e.g., JBIG2 usage + odd dimensions + JavaScript present – that trio would strongly indicate a possible attack. Notably, antivirus researchers have used such heuristics. In 2011, Avast reported they detected malicious JBIG2-based PDFs with a generic heuristic (they flagged the PDF’s JavaScript or other objects as malicious, even though they didn’t decode the JBIG2 stream)
. This shows that often other parts of the PDF give away the presence of a hidden image exploit (the attackers still needed some JavaScript or abnormal object that AV could catch). Our static approach should mimic this: catch whatever “low-hanging fruit” indicators we can from the PDF structure and metadata.
Dynamic Analysis and Emulation
Static analysis might not be enough to definitively identify an exploit hidden in image data. Dynamic analysis of images involves actually decoding or partially executing the image content in a safe manner to observe anomalies. Since fully decoding every image can be expensive, we suggest doing this conditionally or on-demand (e.g., only for flagged suspicious images, or only when a “deep scan” mode is enabled). Possible dynamic strategies:
Attempt image decoding with safe libraries: We can leverage robust, memory-safe image parsing libraries to decode the image streams and see if they are valid or trigger errors. For example, use a pure Rust JBIG2 decoder to parse a JBIG2 stream. If the decoder fails to parse (or encounters corrupt data), that’s a sign the image was intentionally malformed (benign PDFs usually don’t contain truly invalid images). Similarly, run a JPEG2000 decoding (with a library like OpenJPEG or a Rust decoder) on JPX streams – if it errors out or encounters an out-of-bounds internally (caught by safe code), we flag that. Even if it decodes, we can gather metrics: e.g., “this JPX image has 1 tile that’s 10000x10000 pixels” – which is highly unusual and could have caused an overflow in a weaker parser.
Monitor for decoder exceptions or odd conditions: A dynamic analysis engine can watch for certain conditions:
Parsing errors: As mentioned, any parse error on a critical image could be treated as suspicious (image.decode_error). Legit PDFs occasionally have minor corruption, but if an error occurs in a sensitive codec (JBIG2/JPX), it’s safer to err on caution.
Resource spikes: If decoding an image requires an extremely large allocation (say the image claims it needs a 2GB bitmap), we can stop and mark it (image.resource_exhaustion). That indicates a potential bomb or overflow attempt.
Unexpected content after decoding: If we decode an image and the output is not truly image-like, we may have uncovered hidden data. For instance, decoding the monochrome image in the Avast case yielded bytes that were actually a TIFF exploit file
. In a dynamic analysis scenario, we could take the decoded bits and do a quick check: do they resemble a known file header or script? We might recognize the “TIFF II*” or even plaintext. If yes, raise an alert that the image contained an embedded payload (image.hidden_payload_detected).
JBIG2 structural anomalies: A more specialized dynamic check for JBIG2: count the segments and their types. If a JBIG2 stream has thousands of segments or many symbol dictionary definitions, it could be an exploit encoding (the NSO exploit used a huge number of segments as part of its virtual machine logic). A threshold (e.g., >1000 segments or >100 symbols) could trigger a warning (image.jbig2_many_segments). Also, if our JBIG2 decoder library reports something like “Invalid segment reference” or similar (indicative of the overflow trick
), that’s a strong sign of malicious crafting.
Checking image integrity across libraries: In some cases, comparing how two different decoders handle the image can be insightful. For example, feed the same JPX stream to OpenJPEG and to another decoder; if one accepts and one errors, the file might be exploiting an edge that one is lenient about. However, for our purposes, using one good decoder per format is sufficient for detection, given resource constraints.
Limited execution of image content: In theory, one could emulate the effect of an image on a PDF reader. For instance, implement a mini JBIG2 VM to see if it tries to write beyond bounds. This is complex and likely beyond the scope of our needs (it veers into developing a full-blown fuzzer or emulator, which is too slow for bulk analysis). Instead, focusing on decoding and sanity-checking the content is usually enough to catch known patterns. For example, Project Zero’s analysis of the NSO JBIG2 exploit identified a specific integer overflow when “collating referenced segments”
 – our dynamic analysis might not reproduce the overflow, but if we have a check that notices segment reference counts exceeding normal ranges, we can approximate the detection.
Dynamic analysis of XFA images: If the PDF has XFA (which is XML), we could parse the XFA and extract any <image> or <imagePDF> data (often base64-encoded). Then apply image decoders to that content. An attacker might embed, say, a PNG bomb or a TIFF exploit in XFA. By decoding it in a safe environment, we can identify if it’s malformed or malicious. For instance, decode a suspicious XFA TIFF with a safe TIFF parser – if it fails or if the TIFF has known bad patterns (like overlapping IFD entries, etc.), we flag it. We should also be aware of images embedded in PDF portfolios or attachments, but those are more straightforward (the file is just an embedded binary which our tool might extract anyway).
Performance considerations: We would enable full dynamic decoding only in a “deep scan” mode or when heuristics strongly suggest it. This aligns with the user’s desire to keep default analysis fast. For example, by default, we might parse image headers but not decompress the entire pixel data. If --deep is specified (or an image-specific flag), then we actually decompress images. We can also optimize by targeting dynamic analysis to likely malicious content. E.g., we don’t need to waste time decoding every small DCT image (ordinary JPEGs in PDFs are very common and usually benign). But if a JPEG image is huge (say 50 MB compressed) or has unusual markers, we might check it. For JPX/JBIG2, because of their exploit history, we might by default attempt at least a partial decode of those when found. Heuristic vs. dynamic synergy: Ideally, the static phase identifies which images might be dangerous, and the dynamic phase confirms. For instance, static finds JBIG2 filter with height=1, width=25000 -> dynamic then decodes that JBIG2 and finds it yields suspicious data or is invalid. We then confidently mark that as malicious. Another scenario: static finds an image with JBIG2 but nothing obviously wrong in header -> dynamic still decodes and might catch subtle issues (like an invalid Huffman table in JBIG2 that static can’t see). This two-tier approach catches more without always incurring maximum cost.
Is an Image-Analysis Crate Worth It?
Given the above, adding an image analysis component to sis-pdf is highly advisable. We already have dedicated scanning for JavaScript and fonts – images are the third major vector for PDF malware. The historical and current trends (many CVEs, in-the-wild exploits) show that image-based threats are not theoretical; they are actively used by attackers
. Without image analysis, sis-pdf might miss a whole class of exploits. For example, a malicious PDF with only a JBIG2-based attack (no JavaScript, no suspicious fonts) could slip by a scanner that ignores image streams. This is not uncommon: some modern attacks avoid JavaScript to evade detection (e.g., the NSO exploit was pure image and no JS). To achieve comprehensive coverage, sis-pdf should inspect images alongside scripts and fonts. Performance is a concern – thorough image analysis can be slow – but we can design the feature to be selective and optional. By default, we use fast static checks (minimal overhead) and don’t fully decode images unless needed, preserving the “fast analysis in bulk” principle. Users dealing with bulk PDF collections can get quick results with static heuristics (which are relatively lightweight, just parsing object metadata and maybe peeking at a few bytes of streams). Then, for high-risk files or targeted investigations, a --deep mode can enable the heavier dynamic decoding. This is analogous to how sis-pdf likely handles JavaScript: quick static analysis vs. optional sandbox execution. The attack surface across PDF readers is too significant to ignore – images engage huge codebases (hundreds of thousands of lines across all codecs
), and as such are likely to keep yielding exploits. Incorporating image analysis aligns with sis-pdf’s goal of proactive threat detection. It will allow us to catch things like: an embedded exploit image that antivirus might miss, or a stealth payload hidden in image data. It also complements the font and JS analysis: often, a PDF attack might involve multiple components (font + image, or image + JS), and having detectors for all three means we can correlate signals (e.g., both a weird font and a suspicious image present – likely very malicious). In conclusion, adding an image-analysis crate is worth the effort. It will close a blind spot in our PDF scanning and strengthen sis-pdf’s detection against image-borne exploits and malware. The remainder of this answer outlines a detailed technical specification for how such a crate can be developed and integrated.
Technical Specification: image-analysis Crate Design
To integrate image scanning into sis-pdf, we propose creating a new Rust crate (module) named image-analysis within the sis-pdf workspace. This crate will mirror the approach taken by the existing js-analysis and font-analysis crates – providing both static and (optional) dynamic analysis of PDF images, with a clear API that the main sis-pdf scanning engine can call. Below is a detailed plan covering scope, functionality, and integration:
1. Scope and Supported Formats
The image-analysis crate will handle all image formats that can be present in PDFs, including:
JPEG (DCTDecode) – Baseline and progressive JPEG streams.
JPEG2000 (JPXDecode) – Including raw codestreams and JP2 boxed format.
JBIG2 (JBIG2Decode) – Monochrome image decoder streams, including any JBIG2 Globals.
CCITT Fax (CCITTFaxDecode) – Group3/Group4 Fax compressed images (often TIFF internally).
PNG, TIFF, GIF, BMP via XFA or embedded files – If the PDF has an XFA form, extract images (which might be PNG, TIFF, etc.). Also, if images are embedded as file attachments, those can be scanned using this crate’s logic (though attachments might be handled elsewhere).
Other PDF image filters – e.g., RunLengthDecode, LZWDecode, FlateDecode applied to image bitmaps. These are simpler, but we include them to detect things like intentionally malformed PNG-in-Flatestream as in some tricks.
The crate will focus on security-relevant analysis (payload detection) rather than general image processing. We are not aiming to render images or assess their visual contents; instead, we analyze the binary structure for exploits. We will ignore purely social engineering aspects (like a scary image meant to fool a user) because that requires visual analysis and would be out of scope and too expensive.
2. Crate Architecture
We will follow a structure similar to the JS analysis crate plan
:
crates/image-analysis/src/lib.rs – Public API and orchestration.
src/static.rs – Static analysis implementation (format identification, heuristics).
src/dynamic.rs – Dynamic analysis implementation (actual decoding attempts, deeper checks).
src/types.rs – Definitions of structs/enums for image analysis options and results (shared by static and dynamic parts).
2.1 Public API and Types
We define clear data structures and functions for the interface:
Options:
ImageStaticOptions – e.g. booleans or thresholds for certain static checks. (For instance, an option to enable heavy pattern scanning or not.)
ImageDynamicOptions – e.g. a flag to enable dynamic decode, timeouts, memory limits for decoding, etc. Possibly an option to only decode certain formats.
Results/Signals:
ImageStaticResult (or StaticImageSignals) – contains findings from static analysis. This could include a list of detected issues per image object, or aggregated flags.
ImageDynamicResult (or DynamicImageSignals) – details from dynamic analysis, e.g. which images failed to decode, any anomalies found.
Core Functions:
analyze_static_images(doc: &PdfDocument, opts: ImageStaticOptions) -> ImageStaticResult
This function will iterate through all image XObjects in the PDF (and possibly XFA images), apply static checks, and return the collected findings.
analyze_dynamic_images(doc: &PdfDocument, opts: ImageDynamicOptions) -> ImageDynamicResult
This performs the heavier analysis (decoding) on images. It could internally call analyze_static_images first or take cues from a static result to know which images to focus on.
Alternatively, a single entry point analyze_images(doc, static_opts, dynamic_opts) that returns a combined result might be provided for convenience.
This separation means the sis-pdf main program can use static analysis always, and only invoke dynamic when needed (for example, if --deep flag is set, it calls both). The results would include information we can map to sis-pdf’s security event log. For instance, if static analysis finds an image with filter JBIG2, the result might contain a record like {obj 12, issue: "jbig2_used", severity: Low}. Or if dynamic analysis finds a decode error in image X, a record like {obj X, issue: "jpx_parse_error", severity: High}. We will define a set of finding codes similar to how font-analysis defines findings (e.g., font.type1_dangerous_operator in font analysis
). Proposed image finding codes could be:
image.jbig2_present (informational – JBIG2 filter detected),
image.jbig2_malformed (high – JBIG2 stream parsing failed or segments invalid),
image.jbig2_suspect_pattern (high – e.g., single-pixel-high image or excessive segments, indicating possible exploit),
image.jpx_malformed (high – JPX stream failed to parse properly),
image.jpx_large_dims (medium – JPX image with extremely large dimensions or tile sizes),
image.tiff_exploit_pattern (high – detection of known TIFF exploit bytes in an XFA image),
image.unusual_filters (low/med – image uses an unexpected filter combination or multiple layers),
image.steganography_js (medium – if we detect usage of image data by JS, though this might be flagged in JS crate instead),
image.decompression_bomb (medium – image data would expand beyond a safe threshold).
These are examples – we will refine the list based on what our analysis actually checks.
2.2 Static Analysis (static.rs)
Functionality: The static module will contain logic to:
Enumerate image objects in the PDF. Using the PDF parsing core (sis-pdf-core), iterate all PdfObject entries where Type=/XObject and Subtype=/Image. Also retrieve images via form XObjects or patterns if necessary (likely sis-pdf-core already can give us each image stream with its dictionary).
For each image, identify its filter chain (the /Filter entry, which could be an array). Determine the actual format:
If filter includes JBIG2Decode, mark it as JBIG2.
If JPXDecode, mark as JPEG2000.
If DCTDecode, mark as JPEG.
If CCITTFaxDecode, mark as CCITT (TIFF G3/G4).
If only Flate/LZW, then it might be a raw bitmap or an encoded PNG/TIFF; we might inspect the first few bytes of decoded data for known headers (but full decode not in static, unless trivial).
If XFA is present: we parse XFA streams (XML) to find <image> tags, but maybe the PDF parser already surfaces those as streams. If not, static analysis can do a lightweight scan of the XFA XML text for patterns like data:image/ or base64 chunks.
Apply heuristics:
Check image dimensions (/Width, /Height) and BitsPerComponent, /ColorSpace. Flag if width or height is extremely large or if bits/component is unusual (e.g., 1-bit image claiming JBIG2 but width*height yields a huge buffer).
Count number of filters: if more than one filter is applied to the image stream (and especially if one is an image-specific filter), flag image.multiple_filters.
Specific filter rules:
JBIG2: Flag image.jbig2_present for awareness. If /JBIG2Globals is referenced, note that and maybe even statically check its length.
JPX: Flag presence. Possibly peek at the first bytes of the JP2 stream (JP2 header starts with magic \x00\x00\x00\x0cjP \r\n\x87\n). We can extract the declared image size from the JP2 header (if present) by reading the IHDR box (width, height) without full decode – this is a small parse. If width or height >, say, 10000 or if any JP2 box is malformed (we can try to parse structure), flag image.jpx_header_anomaly.
CCITT: Check /K parameter (for Fax, K can be negative or positive for different encodings). Unusually large /Columns or /Rows values (if provided) could be flagged.
DCT (JPEG): Not many static checks unless we want to parse the JPEG header. We could at least verify the presence of markers (0xFFD8 at start, 0xFFD9 end). If the JPEG stream is truncated or has junk after EOI, that’s suspicious.
Look for textual patterns in image streams (limited). For example, if an image is FlateDecoded, we might decompress just a small portion (first few KB) to see if it’s actually ASCII. If yes, and if that ASCII contains JavaScript or HTML-looking content, the image might be carrying something hidden. This would be optional because decompression can be heavy; but Flate decompression of a few KB is usually fast.
Correlate with document-level info: if the PDF catalog or pages reference a name object like “/Names /JavaScript” or if OpenAction contains JavaScript, and we also have a risky image, we might add a combined finding (the integration layer can do this correlation too).
Efficiency: All these static checks are O(n) in number of images and do minimal data decoding, so they’re quite fast. We will implement them in a way to short-circuit heavy work. For example, we won’t decompress an entire image stream at static stage, maybe just sniff headers. We will rely on Rust crates for parsing where possible (e.g., a small JP2 parser snippet for header, or using hayro-jpeg2000 in a mode where it only reads header metadata).
Crates/Dependencies for static phase: Mostly none heavy – we can parse bits ourselves or use small helper crates:
Possibly use hayro-jbig2 in a minimal way to read the JBIG2 globals segment count (but it might be easier to just not decode here).
Use jpeg-decoder crate to parse JPEG metadata (it can parse headers without decoding full image).
Use a tiny portion of png crate to validate PNG header if needed.
However, adding many crate dependencies for static is not strictly necessary if we just do manual header checks, since static is anyway just a prelude to dynamic.
2.3 Dynamic Analysis (dynamic.rs)
Functionality: The dynamic module will provide the analyze_dynamic functionality, which actually attempts to parse or decode images flagged or as requested. Key tasks:
For each image (or each image flagged by static analysis, depending on implementation decision):
Choose the appropriate decoder based on format:
JBIG2: Use a Rust JBIG2 decoder (for example, the hayro-jbig2 crate, which is a memory-safe pure Rust JBIG2 decoder)
. We feed it the image stream bytes (and any JBIG2Globals if present) and attempt a full decode. We catch any errors/exceptions. If decoding fails (throws an error), we record a finding image.jbig2_parse_error (High severity, since a valid JBIG2 image should decode correctly – an error could mean the stream is intentionally crafted to break decoders). If it succeeds, we can retrieve properties: number of pages/segments decoded, etc. We can then apply heuristics on the decoded data: e.g., if the decoder yields N symbol dictionaries and M segments, and N or M exceed normal ranges, flag that (even if it didn’t outright error, it might be suspicious). We might also compare the decoded bitmap count vs. expected page count; any inconsistency might hint at an exploit (some JBIG2 exploits mess with segment referencing).
JPEG2000: We have options – use jpeg2k crate (which wraps OpenJPEG) or a pure Rust decoder like hayro-jpeg2000. Given safety and stability, hayro-jpeg2000 (if mature) would be ideal as it won’t crash on bad input. We attempt to decode the image (or at least decode the structure and first tile). If an error or panic occurs in the decoder (which should be caught as a Result in Rust), we flag image.jpx_decode_error. If it succeeds, we gather the image’s properties (resolution, number of components). Additionally, we can run integrity checks: for example, verify that the image’s dimensions match what the PDF dictionary said (mismatch could indicate an exploit where the PDF header lies about size to allocate a wrong buffer). If there’s a mismatch or other anomalies (like the decoder had to apply error corrections), those are noted.
PNG/TIFF (XFA images): Use existing image crates (png crate for PNG, tiff crate for TIFF) to parse the data. If the PDF’s XFA image (say we base64-decoded a PNG) fails to parse or has suspicious chunks (e.g., a PNG with a very large zTXT chunk which could be hiding data), we flag it. For TIFF, if the tiff crate throws an error (like “unsupported feature” or “corrupt directory”), flag it – many TIFF exploits will cause parsing errors in strict decoders.
JPEG (baseline): Use jpeg-decoder to decode the image fully (or at least to verify all segments are well-formed). It’s rare to have exploits in baseline JPEG in PDF (most were in JPEG2000 instead), but we can still check. If jpeg::Decoder fails (say the JPEG is malformed), we might treat it as suspicious (image.jpeg_corrupt). That said, a corrupt JPEG could also just be a badly created PDF – we might give this a low severity unless paired with other signs.
CCITT Fax: Implement a simple decoder or use an existing one (there is a CCITT decoder in some image libraries, possibly in tiff crate). If decoding yields an error (like if the fax bitstream is invalid), flag it – an intentionally invalid fax stream could be trying to exploit a reader bug. If it decodes, we check output size vs. expected size.
While decoding, enforce safety limits: If an image is huge, we don’t actually allocate an enormous buffer – instead, we rely on the decoder to error out or we abort if dimensions exceed a configured threshold (to avoid excessive memory CPU use in our scanner). For example, set a max pixels limit (like 100 million) and if image exceeds that, skip full decode and just flag it as too large (which itself is an indicator).
Monitor execution time per image: if decoding an image takes too long (due to complexity or our own limit), abort it and record a finding like image.decode_timeout (and perhaps treat it as suspicious because extremely slow decoding could indicate a crafted pathological image).
Combine dynamic findings: We will output a list of images with issues. For each image, possible dynamic findings include:
image.jbig2_exec_code (the extreme case: if we somehow detect a JBIG2 stream writing outside bounds – but detecting that exactly might not be feasible without instrumenting the decoder in detail).
More realistically: image.jbig2_invalid_segments (the decoder encountered invalid data or references – likely an exploit).
image.jpx_invalid (decoder said data is corrupt).
image.decode_failed (general catch-all if any image failed to decode properly).
image.too_large_to_decode (if we bailed out due to size limits).
image.hidden_data_detected (if, after decoding, we found an embedded known pattern like a script or file – this would require scanning the decoded bytes, which we can do for monochrome images or for images with steganographic hints).
Also, if dynamic analysis confirms static suspicions (e.g., static flagged a weird JBIG2, and dynamic confirms parse error), we may elevate the severity in the output.
Crates/Dependencies for dynamic phase: We will leverage existing Rust libraries where possible for safety:
hayro-jbig2 – pure Rust JBIG2 decoder
.
hayro-jpeg2000 or jpeg2k – for JPEG2000. (Note: OpenJPEG via FFI is an option, but it’s C code with a history of security issues
. A memory-safe pure Rust decoder is preferable for our analysis to avoid false positives from crashes in the tool. The hayro-jpeg2000 crate claims to be pure Rust and could be used if stable.)
image crate or specific png, tiff crates – to decode PNG, TIFF, etc.
jpeg-decoder – to handle JPEG.
Possibly jbig2dec-sys (Rust binding to C jbig2dec library) as a fallback if the pure Rust one is incomplete, but using a C lib in analysis runs the risk of that library crashing on malicious input (not ideal inside our scanner process). We will aim for pure Rust decoders to maintain the robustness of sis-pdf (no crash just from scanning a bad file!).
We should feature-gate these decoders in Cargo features, so that the binary can be built without heavy dependencies if image analysis is not needed. For example, a feature flag image-analysis could pull in hayro-jbig2, hayro-jpeg2000, etc., and by default we could keep them off to minimize bloat for users not using this feature. (Sis-pdf can enable it by default in releases if desired, but having the option is good.)
3. Integration with sis-pdf
The new crate will integrate into the sis-pdf scanning pipeline similarly to how js_analysis and font_analysis do:
Configuration and Flags: We will introduce a command-line flag or config setting to control dynamic image analysis. For example, reuse the --deep flag (which might already trigger deep JS sandboxing) to also trigger image dynamic decoding. Additionally, we could have a specific flag like --no-image-dynamic if users want deep scan for scripts but not images, etc., but initially --deep can cover all dynamic analyses. Static image analysis will run by default on every scan (its performance impact is low).
Invocation: In the sis-pdf-detectors (or main scanning logic), after the PDF is parsed:
Call image_analysis::analyze_static_images(document, static_opts) to get static signals. This will yield any immediate findings which we add to the SecurityEvents list (with domain "Image"). For example, if an image uses JBIG2, we log a SecurityEvent: domain=Image, code=image.jbig2_present, severity=Info or Low, message "PDF contains JBIG2-compressed image (possible attack surface)". If an image looks very suspicious statically, we might mark it with higher severity (e.g., "Image XObject has anomalous dimensions suggestive of hidden data").
If dynamic analysis is enabled, call image_analysis::analyze_dynamic_images(document, dyn_opts) next. We might pass along the static results so that dynamic analysis knows which images to focus on (for efficiency). The dynamic function will then attempt decodes and return findings. We then merge those into the SecurityEvents. For example, if image object 5 failed JPX decoding with an out-of-bounds error, we log an event: code=image.jpx_malformed, severity=High, description "Embedded JPEG2000 image stream 5 is malformed (potential exploit)".
Security Log Integration: We will extend sis_pdf_core::security_log::SecurityDomain with an entry for Images (if not already). The findings from image-analysis will be categorized under this domain. In sis-pdf’s output (JSON or text report), new sections or fields for image findings will appear, akin to how JS and font findings are reported. We will also update docs/findings.md to document the new finding codes and their meanings (just as new font checks were documented
).
Performance/Scheduling: Because image dynamic analysis can be slow, we might parallelize it. We can leverage rayon or similar to decode multiple images concurrently (since images are independent). If a PDF has many images, parallel decoding will speed up deep scan (but also use more CPU). We need to be mindful of not exhausting resources; we could limit concurrency or use a thread pool of limited size. The design can borrow from how JS sandbox might run (perhaps sequentially if needed, or parallel if using rayon as indicated by font plan for parallel analysis
).
Cross-module correlation: The integration can also consider cross-correlating image findings with others:
If we found image.jbig2_malformed and the JS analysis crate found js.heap_spray or similar, we might elevate the severity or produce a combined insight that this PDF likely is exploiting an image vulnerability with script. We could implement this in the detectors layer: after getting all findings, if certain combinations occur, add a synthesized finding (like multi.vector_combo).
Likewise, if image analysis finds something and font analysis does too, that PDF is extremely suspect (maybe multiple exploits).
However, initial implementation can treat each domain separately and trust the analyst to notice multiple flags.
Output to Users: The sis command-line could present a summary of image analysis. For instance, if running sis scan --deep file.pdf, the output might include lines such as:
Image 12: JBIG2 image detected (1x25000 px monochrome) – **Suspicious dimensions**
Image 12: JBIG2 parsing **failed** (invalid segment reference) – **Malicious JBIG2 stream**
Image 15: JPEG2000 decode error – **Malformed JP2 stream**
These would be derived from the findings we log. In JSON output, it would likely appear under a findings array with type/image and severity.
Testing & QA: We will craft tests for the image-analysis module:
Unit tests with synthetic PDFs or image streams. For example, create a minimal PDF object stream with JBIG2 filter and feed known-bad data to ensure our static analysis flags it. We can also embed a small valid JBIG2 to ensure no false positive.
Use known malicious samples (if available in a safe form): e.g., a JBIG2 exploit PoC, a JPEG2000 PoC, and verify that our tool catches the indicators (without actually executing anything unsafe). If possible, take the JBIG2 sample from Metasploit (there is a module for the 2009 JBIG2 exploit
) and run our static analysis to see if we flag the presence of 4 JBIG2 streams or unusual sizes as Sophos did
.
Test performance on large benign PDFs with many images to ensure the overhead is acceptable when dynamic mode is off (it should mostly just parse dictionaries, negligible overhead). With dynamic on, measure a few cases to calibrate defaults.
4. Development Plan & Integration Steps
To implement the above in our codebase:
Create the Crate: Add crates/image-analysis in the workspace. Define the Cargo.toml with features for each image format decoder (e.g., jpeg2000, jbig2, png, etc., so we can toggle them). Implement lib.rs to expose analyze_static and analyze_dynamic as described.
Static analysis implementation: Write functions to iterate images. We might utilize existing PDF parsing from sis_pdf_core – for example, if sis-pdf provides a list of objects or a way to query for all XObject Images. Otherwise, use the PdfDocument structure to find them. Implement the checks (dimensions, filter types, etc.). Use log::debug! or tracing to log intermediate info (helpful for debugging analysis logic).
Dynamic analysis implementation: Integrate the image decoding libraries. Ensure to handle errors gracefully (wrap calls in std::panic::catch_unwind if using any FFI or unsafe just in case, but ideally pure Rust crates won’t panic on bad input). Implement timeouts by perhaps running decoders in a limited thread or checking elapsed time if a decoder allows incremental decoding.
Thread-safety: If using rayon to parallelize decoding, ensure the decoder libraries are thread-safe (most pure Rust image crates are, but FFI wrappers may not be).
Integrate with main sis-pdf: Modify sis-pdf-detectors or scanning code to call our crate. Likely in the main scan loop, after processing other elements, insert:
let img_static = image_analysis::analyze_static_images(&pdf, static_opts);
for finding in img_static.findings() {
    security_log.push(finding);
}
if config.dynamic_image_scan {
    let img_dynamic = image_analysis::analyze_dynamic_images(&pdf, dyn_opts);
    for finding in img_dynamic.findings() {
        security_log.push(finding);
    }
}
Also handle any printing or JSON serialization (if new finding types need to be added to the schema). We’ll update the SecurityEvent or similar structure to include an Image category and the specifics (object number, description, etc.).
Update Documentation: Add the new finding codes to docs/findings.md and maybe write a short section in the user guide about the --deep scan now including image checks, and note any new options like --image-formats if we add something like that.
Testing & Tuning: Run the updated sis-pdf on a mix of files:
Clean PDFs with many images (to ensure performance overhead is acceptable and no false alarms).
Known malicious PDF samples (to see if we catch the indicators). If actual samples are not available, create contrived ones: e.g., insert a JBIG2 stream from the spec with slight corruption to see if we flag it.
Edge cases: PDF with an extremely large image (to test our handling of bombs), PDF with unusual color spaces (like ICC based images – ensure we don’t crash if we see an /ICCBased color space, we might ignore ICC content or limit its parsing as out of scope).
XFA containing images: craft an XFA form with a dummy PNG and see that our static finds it and dynamic can decode it.
By following these steps, we add a robust image-analysis capability to sis-pdf. The result will be a new crate that works analogously to the JS and font analysis crates: it encapsulates all image-related detection logic in one place, making the system easier to maintain and extend. The primary goal is seamless integration – from the user’s perspective, running sis-pdf on a file will now include image exploit detection in the output, without needing separate tools.
Conclusion
Images in PDFs present a significant attack surface that has been exploited in the past and continues to pose threats today. We have examined the historical context (e.g., JBIG2 and JPEG2000 exploits) and the modern landscape (sophisticated attacks like the JBIG2-based FORCEDENTRY), and we see that malicious PDFs often use images to carry or trigger exploits. We discussed how these exploits work and how they can be detected via static heuristics and dynamic analysis. Considering the security benefits and the design principles of sis-pdf, adding an image-analysis module is justified. The proposed image-analysis crate would enable sis-pdf to detect image-borne threats by scanning image streams at both binary and high-level (metadata) perspectives, with minimal impact on performance for default scans (static checks) and the ability to opt into deeper analysis when needed. The specification outlined above provides a roadmap for implementing this feature: from identifying suspicious image constructs to decoding them with safe libraries, and integrating findings into the overall security report. By implementing this, sis-pdf will gain parity with its JavaScript and font detectors, offering comprehensive coverage of all primary PDF exploit vectors – scripts, fonts, and images. In effect, this will future-proof the system against image-based malware campaigns and give analysts using sis-pdf deeper insight into any hidden image shenanigans within PDFs. It strikes a balance between thoroughness (catching even the stealthy cases) and performance (avoiding heavy processing unless requested), in line with sis-pdf’s design goals. Ultimately, an image-analysis capability will enhance sis-pdf’s effectiveness as a bulk PDF malware scanner, helping uncover exploits that might otherwise go unnoticed, and thereby improving defenses against PDF-borne attacks now and in the future. Sources:
Liu, Ke. “Dig Into the Attack Surface of PDF and Gain 100+ CVEs in 1 Year.” BlackHat Asia 2017 – describing numerous PDF vulnerabilities in images, fonts, etc
.
CISA Vulnerability Note VU#905281 – Adobe Reader/Acrobat JBIG2 buffer overflow (CVE-2009-0658) exploited by malware in 2009
.
Project Zero Blog – “A deep dive into an NSO zero-click iMessage exploit (FORCEDENTRY)” – details of the JBIG2-based PDF exploit (CVE-2021-30860)
.
SonicWall Threats Research – Analysis of CVE-2018-4990 (JPEG2000 exploit combined with JavaScript)
.
Cyware news – “Steganography hides PDF exploits” – on hiding JS in PDF images (EdgeSpot research)
.
Avast Blog – “Another nasty trick in malicious PDF” – describes using JBIG2 to hide a TIFF exploit (CVE-2010-0188)
.
BlackHat Asia 2017 Whitepaper by Liu – notes on image codec libraries in Acrobat (libtiff, etc.) and a libtiff exploit CVE-2016-5875 affecting multiple readers
.
Citations

CVE-2009-0658 : Buffer overflow in Adobe Reader 9.0 and earlier, and Acrobat 9.0 and earlier, al

https://www.cvedetails.com/cve/CVE-2009-0658/

Exploit for PDF vulnerability CVE-2018-4990 exists in the wild

https://www.sonicwall.com/blog/exploit-for-pdf-vulnerability-cve-2018-4990-exists-in-the-wild

Exploit for PDF vulnerability CVE-2018-4990 exists in the wild

https://www.sonicwall.com/blog/exploit-for-pdf-vulnerability-cve-2018-4990-exists-in-the-wild

Another nasty trick in malicious PDF

https://blog.avast.com/2011/04/22/another-nasty-trick-in-malicious-pdf/
Cybercriminals use Steganography technique to hide PDF exploits | Cyware Alerts - Hacker News

https://social.cyware.com/news/cybercriminals-use-steganography-technique-to-hide-pdf-exploits-c7d382e4
Cybercriminals use Steganography technique to hide PDF exploits | Cyware Alerts - Hacker News

https://social.cyware.com/news/cybercriminals-use-steganography-technique-to-hide-pdf-exploits-c7d382e4
Cybercriminals use Steganography technique to hide PDF exploits | Cyware Alerts - Hacker News

https://social.cyware.com/news/cybercriminals-use-steganography-technique-to-hide-pdf-exploits-c7d382e4
Cybercriminals use Steganography technique to hide PDF exploits | Cyware Alerts - Hacker News

https://social.cyware.com/news/cybercriminals-use-steganography-technique-to-hide-pdf-exploits-c7d382e4

Another nasty trick in malicious PDF

https://blog.avast.com/2011/04/22/another-nasty-trick-in-malicious-pdf/

Another nasty trick in malicious PDF

https://blog.avast.com/2011/04/22/another-nasty-trick-in-malicious-pdf/
Dig Into The Attack Surface of PDF and Gain 100+ CVEs in 1 Year

https://blackhat.com/docs/asia-17/materials/asia-17-Liu-Dig-Into-The-Attack-Surface-Of-PDF-And-Gain-100-CVEs-In-1-Year-wp.pdf

NSO Zero-Click Exploit: Turing-Complete CPU in Image File - Security Boulevard

https://securityboulevard.com/2021/12/nso-zero-click-exploit-turing-complete-cpu-in-image-file/

NSO Zero-Click Exploit: Turing-Complete CPU in Image File - Security Boulevard

https://securityboulevard.com/2021/12/nso-zero-click-exploit-turing-complete-cpu-in-image-file/

NSO Zero-Click Exploit: Turing-Complete CPU in Image File - Security Boulevard

https://securityboulevard.com/2021/12/nso-zero-click-exploit-turing-complete-cpu-in-image-file/

NSO Zero-Click Exploit: Turing-Complete CPU in Image File - Security Boulevard

https://securityboulevard.com/2021/12/nso-zero-click-exploit-turing-complete-cpu-in-image-file/
Dig Into The Attack Surface of PDF and Gain 100+ CVEs in 1 Year

https://blackhat.com/docs/asia-17/materials/asia-17-Liu-Dig-Into-The-Attack-Surface-Of-PDF-And-Gain-100-CVEs-In-1-Year-wp.pdf
Dig Into The Attack Surface of PDF and Gain 100+ CVEs in 1 Year

https://blackhat.com/docs/asia-17/materials/asia-17-Liu-Dig-Into-The-Attack-Surface-Of-PDF-And-Gain-100-CVEs-In-1-Year-wp.pdf

CVE-2017-3044 : Adobe Acrobat Reader versions 11.0.19 and ...

https://www.cvedetails.com/cve/CVE-2017-3044/

A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution - Project Zero

https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html
Dig Into The Attack Surface of PDF and Gain 100+ CVEs in 1 Year

https://blackhat.com/docs/asia-17/materials/asia-17-Liu-Dig-Into-The-Attack-Surface-Of-PDF-And-Gain-100-CVEs-In-1-Year-wp.pdf
Dig Into The Attack Surface of PDF and Gain 100+ CVEs in 1 Year

https://blackhat.com/docs/asia-17/materials/asia-17-Liu-Dig-Into-The-Attack-Surface-Of-PDF-And-Gain-100-CVEs-In-1-Year-wp.pdf
Dig Into The Attack Surface of PDF and Gain 100+ CVEs in 1 Year

https://blackhat.com/docs/asia-17/materials/asia-17-Liu-Dig-Into-The-Attack-Surface-Of-PDF-And-Gain-100-CVEs-In-1-Year-wp.pdf

Another nasty trick in malicious PDF

https://blog.avast.com/2011/04/22/another-nasty-trick-in-malicious-pdf/

Another nasty trick in malicious PDF

https://blog.avast.com/2011/04/22/another-nasty-trick-in-malicious-pdf/
Dig Into The Attack Surface of PDF and Gain 100+ CVEs in 1 Year

https://blackhat.com/docs/asia-17/materials/asia-17-Liu-Dig-Into-The-Attack-Surface-Of-PDF-And-Gain-100-CVEs-In-1-Year-wp.pdf
Dig Into The Attack Surface of PDF and Gain 100+ CVEs in 1 Year

https://blackhat.com/docs/asia-17/materials/asia-17-Liu-Dig-Into-The-Attack-Surface-Of-PDF-And-Gain-100-CVEs-In-1-Year-wp.pdf

A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution - Project Zero

https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html

A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution - Project Zero

https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html

Exploit for PDF vulnerability CVE-2018-4990 exists in the wild

https://www.sonicwall.com/blog/exploit-for-pdf-vulnerability-cve-2018-4990-exists-in-the-wild
Dig Into The Attack Surface of PDF and Gain 100+ CVEs in 1 Year

https://blackhat.com/docs/asia-17/materials/asia-17-Liu-Dig-Into-The-Attack-Surface-Of-PDF-And-Gain-100-CVEs-In-1-Year-wp.pdf

A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution - Project Zero

https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html

A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution - Project Zero

https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html

A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution - Project Zero

https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html

A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution - Project Zero

https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html

Another nasty trick in malicious PDF

https://blog.avast.com/2011/04/22/another-nasty-trick-in-malicious-pdf/

Another nasty trick in malicious PDF

https://blog.avast.com/2011/04/22/another-nasty-trick-in-malicious-pdf/

Exploit for PDF vulnerability CVE-2018-4990 exists in the wild

https://www.sonicwall.com/blog/exploit-for-pdf-vulnerability-cve-2018-4990-exists-in-the-wild

Another nasty trick in malicious PDF

https://blog.avast.com/2011/04/22/another-nasty-trick-in-malicious-pdf/

Exploit for PDF vulnerability CVE-2018-4990 exists in the wild

https://www.sonicwall.com/blog/exploit-for-pdf-vulnerability-cve-2018-4990-exists-in-the-wild

Exploit for PDF vulnerability CVE-2018-4990 exists in the wild

https://www.sonicwall.com/blog/exploit-for-pdf-vulnerability-cve-2018-4990-exists-in-the-wild
Cybercriminals use Steganography technique to hide PDF exploits | Cyware Alerts - Hacker News

https://social.cyware.com/news/cybercriminals-use-steganography-technique-to-hide-pdf-exploits-c7d382e4

CVE-2009-0658 : Buffer overflow in Adobe Reader 9.0 and earlier, and Acrobat 9.0 and earlier, al

https://www.cvedetails.com/cve/CVE-2009-0658/
Cybercriminals use Steganography technique to hide PDF exploits | Cyware Alerts - Hacker News

https://social.cyware.com/news/cybercriminals-use-steganography-technique-to-hide-pdf-exploits-c7d382e4

Exploit for PDF vulnerability CVE-2018-4990 exists in the wild

https://www.sonicwall.com/blog/exploit-for-pdf-vulnerability-cve-2018-4990-exists-in-the-wild

Another nasty trick in malicious PDF

https://blog.avast.com/2011/04/22/another-nasty-trick-in-malicious-pdf/

A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution - Project Zero

https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html

NSO Zero-Click Exploit: Turing-Complete CPU in Image File - Security Boulevard

https://securityboulevard.com/2021/12/nso-zero-click-exploit-turing-complete-cpu-in-image-file/

A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution - Project Zero

https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html
GitHub
000000-js-analysis-crate.md

https://github.com/michiel/sis-pdf/blob/aba05acd05ad26e0c3ee9fb40c7f8cce7805498f/plans/000000-js-analysis-crate.md#L8-L16
GitHub
000000-js-analysis-crate.md

https://github.com/michiel/sis-pdf/blob/aba05acd05ad26e0c3ee9fb40c7f8cce7805498f/plans/000000-js-analysis-crate.md#L20-L28
GitHub
20260115-font-improvement-plan.md

https://github.com/michiel/sis-pdf/blob/aba05acd05ad26e0c3ee9fb40c7f8cce7805498f/plans/20260115-font-improvement-plan.md#L48-L56

hayro-jbig2 - crates.io: Rust Package Registry

https://crates.io/crates/hayro-jbig2

Wanted: a good JPEG 2000 decoder for Rust. · Issue #124 - GitHub

https://github.com/rust-gamedev/wg/issues/124
GitHub
20260115-font-improvement-plan.md

https://github.com/michiel/sis-pdf/blob/aba05acd05ad26e0c3ee9fb40c7f8cce7805498f/plans/20260115-font-improvement-plan.md#L65-L72
GitHub
20260115-font-improvement-plan.md

https://github.com/michiel/sis-pdf/blob/aba05acd05ad26e0c3ee9fb40c7f8cce7805498f/plans/20260115-font-improvement-plan.md#L90-L98

CVE-2009-0658 : Buffer overflow in Adobe Reader 9.0 and earlier, and Acrobat 9.0 and earlier, al

https://www.cvedetails.com/cve/CVE-2009-0658/

Analysis of CVE-2009-0658 (Adobe Reader 0day) | SOPHOS

