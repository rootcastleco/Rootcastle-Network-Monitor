Imports System.Windows.Threading

Class Application

    Private Sub Application_DispatcherUnhandledException(sender As Object, e As DispatcherUnhandledExceptionEventArgs)
        MessageBox.Show($"Error: {e.Exception.Message}{vbCrLf}{vbCrLf}Stack: {e.Exception.StackTrace}", "Error", MessageBoxButton.OK, MessageBoxImage.Error)
        e.Handled = True
    End Sub

End Class
