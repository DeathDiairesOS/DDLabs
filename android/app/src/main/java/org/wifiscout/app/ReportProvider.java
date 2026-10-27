package org.wifiscout.app;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/** Shares only explicitly exported reports through temporary, read-only URI grants. */
public final class ReportProvider extends ContentProvider {
    private static final Pattern NAME = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.json");
    private static final String MIME = "application/json";
    private static final String DIRECTORY = "shared-reports";
    private static final int MAX_REPORTS = 5;

    @Override public boolean onCreate() { return true; }

    /** Called only by the app after its explicit export disclosure is confirmed. */
    static Uri writeReport(Context context, String json) throws IOException {
        File directory = reportDirectory(context);
        if (!directory.isDirectory() && !directory.mkdirs()) {
            throw new IOException("Could not prepare the private report cache.");
        }
        File[] entries = directory.listFiles();
        List<File> reports = new ArrayList<>();
        if (entries != null) {
            for (File entry : entries) {
                if (NAME.matcher(entry.getName()).matches() && entry.isFile()
                        && directory.equals(entry.getCanonicalFile().getParentFile())) {
                    reports.add(entry);
                }
            }
        }
        reports.sort(Comparator.comparingLong(File::lastModified));
        // Only our UUID-named private-cache files are eligible for deletion.
        // This runs on a new explicit export, never against external documents.
        for (int i = 0; i <= reports.size() - MAX_REPORTS; i++) {
            if (!reports.get(i).delete()) {
                throw new IOException("Could not clear an older private report export.");
            }
        }
        String filename = UUID.randomUUID().toString() + ".json";
        File file = new File(directory, filename);
        Files.write(file.toPath(), json.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        return new Uri.Builder().scheme("content").authority(context.getPackageName() + ".reports")
                .appendPath(filename).build();
    }

    private static File reportDirectory(Context context) throws IOException {
        File cache = context.getCacheDir().getCanonicalFile();
        File directory = new File(cache, DIRECTORY).getCanonicalFile();
        if (!cache.equals(directory.getParentFile())) {
            throw new IOException("Invalid private report cache.");
        }
        return directory;
    }

    private File resolve(Uri uri) throws FileNotFoundException {
        Context context = getContext();
        if (context == null || !"content".equals(uri.getScheme())
                || !(context.getPackageName() + ".reports").equals(uri.getAuthority())
                || uri.getQuery() != null || uri.getFragment() != null
                || uri.getPathSegments().size() != 1
                || !NAME.matcher(uri.getPathSegments().get(0)).matches()) {
            throw new FileNotFoundException("Invalid report URI.");
        }
        try {
            File directory = reportDirectory(context);
            File file = new File(directory, uri.getPathSegments().get(0)).getCanonicalFile();
            if (!directory.equals(file.getParentFile()) || !file.isFile()) {
                throw new FileNotFoundException("This report is no longer available.");
            }
            return file;
        } catch (IOException error) {
            throw new FileNotFoundException("This report is no longer available.");
        }
    }

    @Override public String getType(Uri uri) {
        try { resolve(uri); }
        catch (FileNotFoundException error) { throw new IllegalArgumentException(error.getMessage()); }
        return MIME;
    }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode)) throw new FileNotFoundException("Report grants are read-only.");
        return ParcelFileDescriptor.open(resolve(uri), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                  String[] selectionArgs, String sortOrder) {
        if (selection != null || selectionArgs != null || sortOrder != null) {
            throw new IllegalArgumentException("Report queries do not support filtering or sorting.");
        }
        File file;
        try { file = resolve(uri); }
        catch (FileNotFoundException error) { throw new IllegalArgumentException(error.getMessage()); }
        String[] columns = projection == null
                ? new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE} : projection;
        Object[] values = new Object[columns.length];
        for (int i = 0; i < columns.length; i++) {
            if (OpenableColumns.DISPLAY_NAME.equals(columns[i])) values[i] = "wifi-scout-report.json";
            else if (OpenableColumns.SIZE.equals(columns[i])) values[i] = file.length();
            else throw new IllegalArgumentException("Unsupported report metadata column.");
        }
        MatrixCursor cursor = new MatrixCursor(columns, 1);
        cursor.addRow(values);
        return cursor;
    }

    @Override public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("Reports are read-only.");
    }

    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) {
        throw new UnsupportedOperationException("Reports are read-only.");
    }

    @Override public int delete(Uri uri, String selection, String[] args) {
        throw new UnsupportedOperationException("Reports are read-only.");
    }
}
