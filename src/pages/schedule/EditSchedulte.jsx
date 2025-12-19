import React, { useContext, useEffect, useState } from "react";
import { IoMdArrowBack } from "react-icons/io";
import { FaPlus } from "react-icons/fa6";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { ModernTimePicker } from "../../components/Picker/TimePicker";
import DatePicker from "../../components/Picker/DatePicker";
import { MyContext } from "../../context/GlobalContext";
import {
  db,
  doc,
  getDownloadURL,
  getMetadata,
  listAll,
  ref,
  storage,
  updateDoc,
  uploadBytesResumable,
} from "../../firbase/FirebaseInit";
import { HiOutlinePencilSquare } from "react-icons/hi2";
import { toast } from "react-toastify";
export default function EditSchedule() {
  const navigate = useNavigate("");
  const { SelectedTime, SelectedDate, Employee } = useContext(MyContext);
  const loc = useLocation();
  const [ImagesPath, setImagesPath] = useState([]);
  const [images, setImages] = useState([]);
  const [Scheduled, setScheduled] = useState({
    description: "",
    images: [],
    time: "",
    date: "",
    type: [],
  });

  async function updateImageNames() {
    const storageRef = ref(storage, "images/");
    const { items } = await listAll(storageRef);
    const filteredImages = items.filter((item) =>
      item.name.includes(loc?.state?.data?.id)
    );
  
    const metadataPromises = filteredImages.map(async (imgPath) => {
      try {
        const metadata = await getMetadata(imgPath);        
        const downloadURL = await getDownloadURL(imgPath);        
        return {
          metadata: {
            name: metadata.name, 
            type: metadata.contentType,
          },
          downloadURL,
        };
      } catch (error) {
        console.error("Error fetching metadata or download URL:", error);
      }
    });  
    const results = await Promise.all(metadataPromises);
    setImagesPath(results);
    const existingImageNames = new Set(images.map((image) => image.name));
    let updatedImg = [];
  
    // Filter out images that are already in the images state
    const img_data = results.filter(
      (item) => item && !existingImageNames.has(item.metadata.name)
    );
  
    // For each new image, fetch its blob and create a file object
    for (const item of img_data) {
      const { metadata, downloadURL } = item;
      
      // Fetch the image blob from the download URL
      const response = await fetch(downloadURL);
      const blob = await response.blob();
      
      // Create a File object with the fetched blob, including the correct content type
      const file = new File([blob], metadata.name, {
        type: metadata.type, // Use the type from the metadata
      });
  
      // Push the newly created file into the updatedImg array
      updatedImg.push(file);
    }
    setImages(updatedImg);
  }
  

  useEffect(() => {
    setScheduled({
      description: loc?.state?.data?.message,
      time: loc?.state?.data?.time,
      date: loc?.state?.data?.date,
      images: loc?.state?.data?.images,
      type: loc?.state?.data?.type,
    });
    updateImageNames();
  }, []);

  const handleImageChange = (e, img) => {
    const filesArray = Array.from(e.target.files);
    const updatedFiles = filesArray.map((file) => {
      return new File([file], img.metadata.name, { type: file.type });
    });

    updatedFiles.forEach((file) => {
      const existingIndex = images.findIndex(
        (image) => image.name === file.name
      );

      if (existingIndex !== -1) {
        setImages((prev) => {
          const newImages = [...prev];
          newImages[existingIndex] = file;
          return newImages;
        });
      } else {
        setImages((prev) => [...prev, file]);
      }
    });
  };

  const HandleUploadAttach = (e) => {
    const filesArray = Array.from(e.target.files);
    
    // Process the files to create new File objects with unique names
    const updatedFiles = filesArray.map((file) => {
      return new File([file], loc.state.data.id + file.name, { type: file.type });
    });
  
    // Loop through the updated files to add them to `images` and `ImagesPath`
    updatedFiles.forEach((file) => {
      setImages((prev) => [...prev, file]);
      const newImageURL = URL.createObjectURL(file);
      setImagesPath((prev) => [
        ...prev,
        {
          metadata: { name: file.name, type: file.type },  // Include file type here
          downloadURL: newImageURL,  // Temporary URL for the image
        },
      ]);
    });
  };
  
  
  const HandleScheduled = async (e) => {
    e.preventDefault();
    console.log(images, "checkImages");
    const scheduledRef = doc(db, loc.state.collection, loc.state.data.docId);
    const imageUrls = [];
    const docType = [];
    const loadingToastId = toast.loading("Uploading...");
    try {
      for (const image of images) {
        const storageRef = ref(storage, `images/${image.name}`);
        await uploadBytesResumable(storageRef, image);
        const url = await getDownloadURL(storageRef);
        imageUrls.push({ url: url, name: image.name });
        docType.push(image.type);
      }
      await updateDoc(scheduledRef, {
        date: SelectedDate,
        time: SelectedTime,
        message: Scheduled.description,
        images: imageUrls,
        type: docType,
        status: "pending",
        createdAt: new Date(),
        employeeId: Employee.id,
      });
      toast.update(loadingToastId, {
        render: "Scheduled successfully!",
        type: "success",
        isLoading: false,
        autoClose: 5000,
      });
      loc.state.collection == "look" ? navigate("/") : navigate("/schedule");
    } catch (error) {
      console.error("Failed to schedule:", error);
      toast.update(loadingToastId, {
        render: "Failed to schedule. Please try again.",
        type: "error",
        isLoading: false,
        autoClose: 5000,
      });
    }
  };
  console.log(ImagesPath,"imagesPathh");
  

  console.log(Scheduled, "getUpdateArray");
  return (
    <div class="bg-[#F7F7F7] h-[90vh] py-5 px-5 ">
      <NavLink
        to={loc.state.collection == "look" ? "/" : "/schedule"}
        className="font-semibold text-[24px] leading-[29px] flex items-center"
      >
        {" "}
        <IoMdArrowBack size={25} className="mr-2" /> Create Message
      </NavLink>

      <div class="bg-[#FFFFFF] mb-3 h-full border rounded-[10px] border-[#E4E4E4] mt-6 px-3 lg:py-5 lg:px-10">
        <form onSubmit={HandleScheduled}>
          <div className="mt-5 grid grid-cols-1 gap-5  lg:grid-cols-2">
            <div className="mb-1 col-span-2">
              <textarea
                type="text"
                id="base-input"
                value={Scheduled.description}
                onChange={(e) =>
                  setScheduled({ ...images, description: e.target.value })
                }
                className="bg-white border border-gray-300 text-gray-900 text-sm rounded-[12px] h-[127px] mt-1  block w-full p-2.5 focus:outline-[#0A8A33]  "
                placeholder="Type Here...."
              ></textarea>
            </div>
            <div className="mb-3 col-span-2">
              <label htmlFor="file">
                <div className="text-[#007AFF] flex items-center cursor-pointer">
                  <FaPlus className="mr-2" /> Attachment
                </div>
                <input
                  type="file"
                  onChange={HandleUploadAttach}
                  className="hidden"
                  id="file"
                  multiple
                />
              </label>
            </div>
            <div className="mb-3 col-span-2">
              <div className="flex items-center flex-wrap gap-2">
                {ImagesPath.map((img, i) => (
                  <div key={i}>
                    <label htmlFor={`file${i}`}>
                      {/* <div className="text-[#007AFF] flex items-center cursor-pointer">
                        <HiOutlinePencilSquare className="mr-2 mb-2" />
                      </div> */}
                      {img.metadata.type.includes("image") ? (
                        <img
                          src={img.downloadURL}
                          alt=""
                          className="h-[100px] w-auto rounded-md"
                        />
                      ) : ( 
                       <img
                          src="/pdf.png"
                          alt=""
                          className="h-[100px] rounded-md"
                        />
                       )}
                      {/* <input
                        type="file"
                        onChange={(e) => handleImageChange(e, img)}
                        className="hidden"
                        id={`file${i}`}
                      /> */}
                    </label>
                  </div>
                ))}
              </div>
            </div>
            <div className="mb-3 grid grid-cols-1  lg:grid-cols-2  col-span-1">
              <DatePicker date={Scheduled.date} />
              <ModernTimePicker time={Scheduled.time} />
            </div>
          </div>
          <div className="flex items-center gap-5 mt-5">
            <button
              type="submit"
              className="text-white bg-[#0A8A33] text-nowrap text-sm lg:text-base rounded-lg  lg:w-[200px] h-[50px]  px-5 py-2.5 text-center"
            >
              Update Message
            </button>
            <NavLink
              to={loc.state.collection == "look" ? "/" : "/schedule"}
              className="bg-[#F1F1F1] font-bold rounded-lg  lg:w-[150px] h-[50px]  px-5 py-2.5 text-sm  lg:text-base text-center"
            >
              Cancel
            </NavLink>
          </div>
        </form>

        <div></div>
      </div>
    </div>
  );
}
