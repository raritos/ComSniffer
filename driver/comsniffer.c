/*
 * ComSniffer.sys — Serial port upper-filter driver v2
 *
 * Captures:
 *   - IRP_MJ_READ  (device → app)
 *   - IRP_MJ_WRITE (app → device)
 *   - IRP_MJ_DEVICE_CONTROL — all serial line setting IOCTLs:
 *       baud rate, parity, stop bits, word length, flow control,
 *       timeouts, DTR/RTS, break signals, queue flush, etc.
 *
 * Log entries go into a 512KB non-paged ring buffer.
 * User space reads via \\.\ComSniffer using plain ReadFile.
 */

#include <ntddk.h>
#include <wdm.h>
#include <ntddser.h>   /* Serial IOCTL definitions + structs */

#define DRIVER_TAG        'fSnC'
#define DEVICE_NAME       L"\\Device\\ComSniffer"
#define SYMLINK_NAME      L"\\DosDevices\\ComSniffer"
#define LOG_BUFFER_SIZE   (1024 * 1024)   /* 1 MB ring buffer */

/* ------------------------------------------------------------------ */
/*  Entry types                                                         */
/* ------------------------------------------------------------------ */
#define ENTRY_TYPE_READ       0x01   /* raw data: device → app        */
#define ENTRY_TYPE_WRITE      0x02   /* raw data: app → device        */
#define ENTRY_TYPE_IOCTL      0x03   /* line-setting IOCTL            */

#pragma pack(push, 1)
typedef struct _LOG_ENTRY {
    LARGE_INTEGER Timestamp;    /* FILETIME (100-ns ticks)            */
    UCHAR         Type;         /* ENTRY_TYPE_*                       */
    ULONG         Code;         /* IOCTL code (0 for data entries)    */
    ULONG         DataLength;   /* bytes following this header        */
    UCHAR         Data[1];
} LOG_ENTRY, *PLOG_ENTRY;
#pragma pack(pop)

#define LOG_ENTRY_HDR_SIZE  (FIELD_OFFSET(LOG_ENTRY, Data))
#define LOG_ENTRY_FULL_SIZE(len) (LOG_ENTRY_HDR_SIZE + (len))

/* ------------------------------------------------------------------ */
/*  Ring buffer                                                         */
/* ------------------------------------------------------------------ */
typedef struct _RING {
    PUCHAR     Buf;
    ULONG      Cap;
    ULONG      WPos;
    ULONG      RPos;
    ULONG      Stored;
    KSPIN_LOCK Lock;
    KEVENT     Ready;
} RING, *PRING;

static RING g_Ring;

static VOID RingWrite(PUCHAR Src, ULONG Len)
{
    ULONG space = g_Ring.Cap - g_Ring.Stored;
    if (Len > space) {
        ULONG drop = Len - space;
        g_Ring.RPos  = (g_Ring.RPos + drop) % g_Ring.Cap;
        g_Ring.Stored -= drop;
    }
    for (ULONG i = 0; i < Len; i++) {
        g_Ring.Buf[g_Ring.WPos] = Src[i];
        g_Ring.WPos = (g_Ring.WPos + 1) % g_Ring.Cap;
    }
    g_Ring.Stored += Len;
}

static ULONG RingRead(PUCHAR Dst, ULONG Max)
{
    ULONG n = min(g_Ring.Stored, Max);
    for (ULONG i = 0; i < n; i++) {
        Dst[i] = g_Ring.Buf[g_Ring.RPos];
        g_Ring.RPos = (g_Ring.RPos + 1) % g_Ring.Cap;
    }
    g_Ring.Stored -= n;
    return n;
}

/* ------------------------------------------------------------------ */
/*  Emit a log entry into the ring                                      */
/* ------------------------------------------------------------------ */
static VOID EmitEntry(UCHAR Type, ULONG IoctlCode,
                      PUCHAR Data, ULONG DataLen)
{
    ULONG total = LOG_ENTRY_FULL_SIZE(DataLen);
    PUCHAR raw  = (PUCHAR)ExAllocatePoolWithTag(
                      NonPagedPoolNx, total, DRIVER_TAG);
    if (!raw) return;

    PLOG_ENTRY e = (PLOG_ENTRY)raw;
    KeQuerySystemTime(&e->Timestamp);
    e->Type       = Type;
    e->Code       = IoctlCode;
    e->DataLength = DataLen;
    if (DataLen && Data)
        RtlCopyMemory(e->Data, Data, DataLen);

    KIRQL irql;
    KeAcquireSpinLock(&g_Ring.Lock, &irql);
    RingWrite(raw, total);
    KeReleaseSpinLock(&g_Ring.Lock, irql);

    ExFreePoolWithTag(raw, DRIVER_TAG);
    KeSetEvent(&g_Ring.Ready, IO_NO_INCREMENT, FALSE);
}

/* ------------------------------------------------------------------ */
/*  Device extension                                                    */
/* ------------------------------------------------------------------ */
typedef struct _DEV_EXT {
    PDEVICE_OBJECT Self;
    PDEVICE_OBJECT Lower;
} DEV_EXT, *PDEV_EXT;

static PDEVICE_OBJECT g_CtrlDev = NULL;

/* ------------------------------------------------------------------ */
/*  READ completion                                                      */
/* ------------------------------------------------------------------ */
static NTSTATUS ReadComplete(PDEVICE_OBJECT DevObj, PIRP Irp, PVOID Ctx)
{
    UNREFERENCED_PARAMETER(DevObj);
    UNREFERENCED_PARAMETER(Ctx);

    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information > 0) {
        PUCHAR buf = NULL;
        if (Irp->MdlAddress)
            buf = (PUCHAR)MmGetSystemAddressForMdlSafe(
                      Irp->MdlAddress, NormalPagePriority);
        else
            buf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;

        if (buf)
            EmitEntry(ENTRY_TYPE_READ, 0, buf,
                      (ULONG)Irp->IoStatus.Information);
    }
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_CONTINUE_COMPLETION;
}

static NTSTATUS SnifferRead(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    DEV_EXT *ext = (DEV_EXT*)DevObj->DeviceExtension;
    if (DevObj == g_CtrlDev) {
        /* Control device read — hand ring data to user space */
        PIO_STACK_LOCATION stk = IoGetCurrentIrpStackLocation(Irp);
        ULONG maxLen = stk->Parameters.Read.Length;
        PUCHAR buf   = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;

        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000LL * 500;   /* 500 ms */
        KeWaitForSingleObject(&g_Ring.Ready, Executive,
                              KernelMode, FALSE, &timeout);

        KIRQL irql;
        ULONG copied;
        KeAcquireSpinLock(&g_Ring.Lock, &irql);
        copied = RingRead(buf, maxLen);
        if (g_Ring.Stored == 0) KeClearEvent(&g_Ring.Ready);
        KeReleaseSpinLock(&g_Ring.Lock, irql);

        Irp->IoStatus.Status      = STATUS_SUCCESS;
        Irp->IoStatus.Information = copied;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ReadComplete, NULL, TRUE, TRUE, TRUE);
    return IoCallDriver(ext->Lower, Irp);
}

/* ------------------------------------------------------------------ */
/*  WRITE intercept                                                      */
/* ------------------------------------------------------------------ */
static NTSTATUS SnifferWrite(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    DEV_EXT *ext = (DEV_EXT*)DevObj->DeviceExtension;
    if (DevObj == g_CtrlDev) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    PIO_STACK_LOCATION stk = IoGetCurrentIrpStackLocation(Irp);
    ULONG len = stk->Parameters.Write.Length;
    if (len > 0) {
        PUCHAR buf = Irp->MdlAddress
            ? (PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority)
            : (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        if (buf)
            EmitEntry(ENTRY_TYPE_WRITE, 0, buf, len);
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->Lower, Irp);
}

/* ------------------------------------------------------------------ */
/*  IOCTL completion — captures the result buffer (GET calls)          */
/* ------------------------------------------------------------------ */
typedef struct _IOCTL_CTX {
    ULONG IoctlCode;
} IOCTL_CTX, *PIOCTL_CTX;

static NTSTATUS IoctlComplete(PDEVICE_OBJECT DevObj, PIRP Irp, PVOID Ctx)
{
    UNREFERENCED_PARAMETER(DevObj);
    PIOCTL_CTX ic = (PIOCTL_CTX)Ctx;

    if (NT_SUCCESS(Irp->IoStatus.Status)) {
        PUCHAR buf    = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        ULONG  outLen = (ULONG)Irp->IoStatus.Information;
        if (buf && outLen)
            EmitEntry(ENTRY_TYPE_IOCTL, ic->IoctlCode, buf, outLen);
        else
            EmitEntry(ENTRY_TYPE_IOCTL, ic->IoctlCode, NULL, 0);
    }

    ExFreePoolWithTag(ic, DRIVER_TAG);
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_CONTINUE_COMPLETION;
}

/*
 * We intercept the following IOCTLs:
 *
 * SET calls — log the INPUT buffer (what the app is setting)
 * GET calls — log the OUTPUT buffer (what the driver returns)
 *             via completion routine
 */
static const ULONG WatchedIoctls[] = {
    IOCTL_SERIAL_SET_BAUD_RATE,
    IOCTL_SERIAL_GET_BAUD_RATE,
    IOCTL_SERIAL_SET_LINE_CONTROL,
    IOCTL_SERIAL_GET_LINE_CONTROL,
    IOCTL_SERIAL_SET_TIMEOUTS,
    IOCTL_SERIAL_GET_TIMEOUTS,
    IOCTL_SERIAL_SET_HANDFLOW,
    IOCTL_SERIAL_GET_HANDFLOW,
    IOCTL_SERIAL_SET_DTR,
    IOCTL_SERIAL_CLR_DTR,
    IOCTL_SERIAL_SET_RTS,
    IOCTL_SERIAL_CLR_RTS,
    IOCTL_SERIAL_SET_BREAK_ON,
    IOCTL_SERIAL_SET_BREAK_OFF,
    IOCTL_SERIAL_PURGE,
    IOCTL_SERIAL_RESET_DEVICE,
    IOCTL_SERIAL_GET_COMMSTATUS,
    IOCTL_SERIAL_GET_MODEMSTATUS,
    IOCTL_SERIAL_SET_QUEUE_SIZE,
    IOCTL_SERIAL_SET_CHARS,
    IOCTL_SERIAL_GET_CHARS,
    IOCTL_SERIAL_LSRMST_INSERT,
    IOCTL_SERIAL_CONFIG_SIZE,
    IOCTL_SERIAL_GET_WAIT_MASK,
    IOCTL_SERIAL_SET_WAIT_MASK,
    0  /* sentinel */
};

static BOOLEAN IsWatched(ULONG code)
{
    for (int i = 0; WatchedIoctls[i]; i++)
        if (WatchedIoctls[i] == code) return TRUE;
    return FALSE;
}

static NTSTATUS SnifferDevCtrl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    DEV_EXT *ext = (DEV_EXT*)DevObj->DeviceExtension;
    if (DevObj == g_CtrlDev) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    PIO_STACK_LOCATION stk  = IoGetCurrentIrpStackLocation(Irp);
    ULONG              code = stk->Parameters.DeviceIoControl.IoControlCode;

    if (!IsWatched(code)) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(ext->Lower, Irp);
    }

    /* For SET-style IOCTLs: log input buffer NOW before passing down */
    ULONG inLen = stk->Parameters.DeviceIoControl.InputBufferLength;
    if (inLen > 0) {
        PUCHAR inBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        if (inBuf)
            EmitEntry(ENTRY_TYPE_IOCTL, code, inBuf, inLen);
        else
            EmitEntry(ENTRY_TYPE_IOCTL, code, NULL, 0);
    }

    /* For GET-style IOCTLs: set completion to capture output buffer */
    ULONG outLen = stk->Parameters.DeviceIoControl.OutputBufferLength;
    if (outLen > 0 && inLen == 0) {
        /* Pure GET — only capture on completion */
        PIOCTL_CTX ic = (PIOCTL_CTX)ExAllocatePoolWithTag(
                            NonPagedPoolNx, sizeof(IOCTL_CTX), DRIVER_TAG);
        if (ic) {
            ic->IoctlCode = code;
            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, IoctlComplete, ic,
                                   TRUE, TRUE, TRUE);
            return IoCallDriver(ext->Lower, Irp);
        }
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->Lower, Irp);
}

/* ------------------------------------------------------------------ */
/*  Pass-through, Create, Close                                         */
/* ------------------------------------------------------------------ */
static NTSTATUS SnifferPassThrough(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    DEV_EXT *ext = (DEV_EXT*)DevObj->DeviceExtension;
    if (DevObj == g_CtrlDev) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->Lower, Irp);
}

static NTSTATUS SnifferCreate(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS SnifferClose(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  AddDevice                                                           */
/* ------------------------------------------------------------------ */
static NTSTATUS SnifferAddDevice(PDRIVER_OBJECT DrvObj,
                                  PDEVICE_OBJECT Pdo)
{
    PDEVICE_OBJECT flt = NULL;
    NTSTATUS s = IoCreateDevice(DrvObj, sizeof(DEV_EXT), NULL,
                                FILE_DEVICE_SERIAL_PORT,
                                FILE_DEVICE_SECURE_OPEN,
                                FALSE, &flt);
    if (!NT_SUCCESS(s)) return s;

    DEV_EXT *ext = (DEV_EXT*)flt->DeviceExtension;
    ext->Self    = flt;
    ext->Lower   = IoAttachDeviceToDeviceStack(flt, Pdo);
    if (!ext->Lower) { IoDeleteDevice(flt); return STATUS_NO_SUCH_DEVICE; }

    flt->Flags |= ext->Lower->Flags & (DO_BUFFERED_IO|DO_DIRECT_IO|DO_POWER_PAGABLE);
    flt->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Unload                                                              */
/* ------------------------------------------------------------------ */
VOID DriverUnload(PDRIVER_OBJECT DrvObj)
{
    UNREFERENCED_PARAMETER(DrvObj);
    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, SYMLINK_NAME);
    IoDeleteSymbolicLink(&sym);
    if (g_CtrlDev)       IoDeleteDevice(g_CtrlDev);
    if (g_Ring.Buf)      ExFreePoolWithTag(g_Ring.Buf, DRIVER_TAG);
}

/* ------------------------------------------------------------------ */
/*  DriverEntry                                                         */
/* ------------------------------------------------------------------ */
NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
    UNREFERENCED_PARAMETER(RegPath);

    /* Ring buffer */
    g_Ring.Buf = (PUCHAR)ExAllocatePoolWithTag(
                     NonPagedPoolNx, LOG_BUFFER_SIZE, DRIVER_TAG);
    if (!g_Ring.Buf) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_Ring.Buf, LOG_BUFFER_SIZE);
    g_Ring.Cap = LOG_BUFFER_SIZE;
    KeInitializeSpinLock(&g_Ring.Lock);
    KeInitializeEvent(&g_Ring.Ready, NotificationEvent, FALSE);

    /* Control device */
    UNICODE_STRING dev, sym;
    RtlInitUnicodeString(&dev, DEVICE_NAME);
    RtlInitUnicodeString(&sym, SYMLINK_NAME);
    NTSTATUS s = IoCreateDevice(DrvObj, 0, &dev,
                                FILE_DEVICE_UNKNOWN,
                                FILE_DEVICE_SECURE_OPEN,
                                FALSE, &g_CtrlDev);
    if (!NT_SUCCESS(s)) {
        ExFreePoolWithTag(g_Ring.Buf, DRIVER_TAG);
        return s;
    }
    g_CtrlDev->Flags |= DO_BUFFERED_IO;
    IoCreateSymbolicLink(&sym, &dev);

    /* Dispatch table */
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DrvObj->MajorFunction[i] = SnifferPassThrough;

    DrvObj->MajorFunction[IRP_MJ_CREATE]         = SnifferCreate;
    DrvObj->MajorFunction[IRP_MJ_CLOSE]          = SnifferClose;
    DrvObj->MajorFunction[IRP_MJ_READ]           = SnifferRead;
    DrvObj->MajorFunction[IRP_MJ_WRITE]          = SnifferWrite;
    DrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SnifferDevCtrl;

    DrvObj->DriverExtension->AddDevice = SnifferAddDevice;
    DrvObj->DriverUnload               = DriverUnload;

    return STATUS_SUCCESS;
}
