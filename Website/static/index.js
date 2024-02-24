function deleteNote(noteId) {
  fetch("/delete-note", {
    //take note id and sends post requestv to the delete note endpoint

    method: "POST",
    body: JSON.stringify({ noteId: noteId }),
  //once it gets response,reloads the window
  }).then((_res) => {
    window.location.href = "/";
  });
}