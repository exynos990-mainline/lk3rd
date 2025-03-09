#include <stdbool.h>
#include <stdio.h>
#include <lk3rd/persistent_storage.h>
#include <lk3rd/theme.h>
#include <lk3rd/display.h>

int lk3rd_set_theme(int theme)
{
	int ret;
    
	persistent_storage_write(LK3RD_SWITCH_THEME, theme);

	ret = persistent_storage_read(LK3RD_SWITCH_THEME);

	if(ret != theme)
	{
		printf("lk3rd: couldn't write to persistent storage, e: %i g: %i\n",
            theme, ret);
        print_lcd_update(FONT_RED, FONT_BLACK, "Failed to write theme to persistent storage, e: %i g: %i", theme, ret);
	}
	return ret;
}

int lk3rd_get_theme()
{
    int theme = persistent_storage_read(LK3RD_SWITCH_THEME);
    if (theme < 0 || theme > THEME_END)
    {
        theme = THEME_SNAPDRAGON;
        lk3rd_set_theme(theme);
    }
	return theme;
}



const char* lk3rd_get_current_theme_name()
{
    int currentTheme = lk3rd_get_theme();
    const char* themeNames[] = {
        "Snapdragon",
        "Pixel     ",
        "Unified   ",
        "Debug     "
    };

    if (currentTheme < 0 || currentTheme >= (int)sizeof(themeNames) / (int)sizeof(themeNames[0])) {
        print_lcd_update(FONT_RED, FONT_BLACK, "Error: Invalid theme index");
        return "Error: Invalid theme index";
    }
    return themeNames[currentTheme];
}

