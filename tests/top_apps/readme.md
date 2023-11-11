# Validation test using top Play Store applications

On 04/11/2023, a comprehensive dataset comprising 1809 applications, exceeding 53GB in total, was retrieved from all categories on the Play Store. The objective is to subject these applications to analysis using apkInspector in conjunction with [androguard](https://github.com/androguard/androguard) and [zipfile](https://docs.python.org/3/library/zipfile.html) for the purpose of validating the accuracy of apkInspector's results.

The methodology involves a dual approach. Firstly, leveraging zipfile, we extracted the contents of each APK. Subsequently, apkInspector was employed for the same task. The ensuing directories from both methods were then compared to ensure the exact same output, thereby validating the consistency of results.

Moving to the second phase, our focus shifts to extracting the AndroidManifest.xml files. This was performed separately using both androguard and apkInspector. The contents of these manifest files was then undergone a thorough comparison utilizing `xml.etree.ElementTree` to verify that they encompass identical elements, adding an additional layer of validation to the analysis process.

The categories from which the applications were retrieved were the following:
~~~~
ANDROID_WEAR
WATCH_FACE
ART_AND_DESIGN
AUTO_AND_VEHICLES
BEAUTY
BOOKS_AND_REFERENCE
BUSINESS
COMICS
COMMUNICATION
DATING
EDUCATION
ENTERTAINMENT
EVENTS
FINANCE
FOOD_AND_DRINK
GAME
Google Cast, we retrieved 0 packages.
HEALTH_AND_FITNESS
HOUSE_AND_HOME
FAMILY
LIBRARIES_AND_DEMO
LIFESTYLE
MAPS_AND_NAVIGATION
MEDICAL
MUSIC_AND_AUDIO
NEWS_AND_MAGAZINES
PARENTING
PERSONALIZATION
PHOTOGRAPHY
PRODUCTIVITY
SHOPPING
SOCIAL
SPORTS
TOOLS
TRAVEL_AND_LOCAL
VIDEO_PLAYERS
WEATHER
~~~~

### The list of all the 1809 application is located [here](./packages_list.txt).



## Zip comparison
Utilizing [filecmp](https://docs.python.org/3/library/filecmp.html) and more specifically the [dircmp](https://docs.python.org/3/library/filecmp.html#filecmp.dircmp) class, we compare the two directories where on the first one we have extracted the apk using [zipfile](https://docs.python.org/3/library/zipfile.html) and on the second we used apkInspector.
~~~~
comparison = filecmp.dircmp(method1_directory, method2_directory)
~~~~

## AndroidManifest comparison
Using `xml.etree.ElementTree` we are parsing the resulting AndroidManifest.xml files from androguard and apkinspector and then compare the elements found in each case. The comparison includes checking every tag along with their attributes and any potential children.
The comparison method looks like the following:
~~~~
def compare_elements(elem1, elem2):
    # Compare tags
    if get_local_name(elem1.tag) != get_local_name(elem2.tag):
        return False

    # Compare attributes
    attrib_names1 = {k for k, v in elem1.attrib.items()}
    attrib_names2 = {k for k, v in elem2.attrib.items()}

    # Compare sets of attribute names
    if attrib_names1 != attrib_names2:
        return False

    # Compare children
    if len(elem1) != len(elem2):
        return False

    for child1, child2 in zip(elem1, elem2):
        if not compare_elements(child1, child2):
            return False

    return True
~~~~


## Results

The results from the test can be seen below:
~~~~
Total Packages Tested: 1809
Successful Unzipping: 1809
Successful Manifest Comparison: 1806
Packages with differences in the AndroidManifest: 3
Packages where androguard failed to parse the AndroidManifest: 0
Packages where apkInspector failed to parse the AndroidManifest: 0
~~~~

 - The `Successful Unzipping` means that 100% of the applications were correctly unzipped.
 - The `Successful Manifest Comparison` means that all applications except three, had the same AndroidManifest.xml file for both androguard and apkInspector.
 - The `Packages with differences in the AndroidManifest` is for the applications that did not have a `Successful Manifest Comparison`.
 - The `Packages where androguard failed to parse the AndroidManifest` and `Packages where apkInspector failed to parse the AndroidManifest` are for the applications that produced an AndroidManifest that for some reason did not have the correct XML format and parsing it using `xml.etree.ElementTree` failed.


The following three are the applications that were marked with a difference in the AndroidManifest:
 - com.paypal.android.p2pmobile.apk
 - by.iba.tapxphone.apk
 - com.playstation.remoteplay.apk

Their logs as to why they failed are similar and as an example one of them is shown:
~~~~
Current APK being processed: com.playstation.remoteplay.apk | 1295/1809
manifest attribute names: {'UNKNOWN_SYSTEM_ATTRIBUTE_01010573', '{http://schemas.android.com/apk/res/android}versionCode', 'versionName', 'platformBuildVersionCode', 'package', 'platformBuildVersionName', 'UNKNOWN_SYSTEM_ATTRIBUTE_01010572'}
manifest attribute names: {'{http://schemas.android.com/apk/res/android}Unknown_Attribute_Name_6402', '{http://schemas.android.com/apk/res/android}Unknown_Attribute_Name_6414', '{http://schemas.android.com/apk/res/android}versionCode', 'platformBuildVersionCode', '{http://schemas.android.com/apk/res/android}Unknown_Attribute_Name_2691', 'package', 'platformBuildVersionName'}
com.playstation.remoteplay.apk: DIFFERENT
~~~~
Their difference comes from the fact that unknown system attributes were detected (the reason why this happens is irrelevant for the purpose of this comparison). Androguard, as can also he seen [here](https://github.com/androguard/androguard/blob/master/androguard/core/axml/__init__.py#L828), marks the unknown attributes with the string `android:UNKNOWN_SYSTEM_ATTRIBUTE_` followed by a hex value, while apkInspector marks it with the string `Unknown_Attribute_Name_` followed by a random four digit number.

Therefore, we can safely assume that even for these three cases the actual manifest is the same for both tools.

**The results of the test indicate that apkInspector can unzip an APK and decode the AndroidManifest.xml reliably and efficiently, comparable to other tools such as androguard.**