package org.nitocore.qt;

import android.os.Bundle;
import android.system.ErrnoException;
import android.system.Os;

import org.qtproject.qt5.android.bindings.QtActivity;

import java.io.File;

public class NitoQtActivity extends QtActivity
{
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        final File nitoDir = new File(getFilesDir().getAbsolutePath() + "/.nito");
        if (!nitoDir.exists()) {
            nitoDir.mkdir();
        }

        super.onCreate(savedInstanceState);
    }
}
