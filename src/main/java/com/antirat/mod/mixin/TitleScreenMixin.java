package com.antirat.mod.mixin;

import com.antirat.mod.gui.NativeSecurityWindow;
import com.antirat.mod.manager.QuarantineManager;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.gui.screen.TitleScreen;
import net.minecraft.text.Text;
import org.lwjgl.glfw.GLFW;
import org.spongepowered.asm.mixin.Mixin;

@Mixin(TitleScreen.class)
public abstract class TitleScreenMixin extends Screen {

    protected TitleScreenMixin(Text title) {
        super(title);
    }

    @Override
    public boolean keyPressed(int keyCode, int scanCode, int modifiers) {
        // Right Shift Keybind trigger for Anti-RAT Security Control Window
        if (keyCode == GLFW.GLFW_KEY_RIGHT_SHIFT) {
            NativeSecurityWindow.showPreLaunchWindow(QuarantineManager.getQuarantinedReports());
            return true;
        }
        return super.keyPressed(keyCode, scanCode, modifiers);
    }
}
